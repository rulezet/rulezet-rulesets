import "pe"
rule winsocks : feature networking windows
{
meta:
	description = "Imports Winsock Library"

condition:
	        uint16be(0) == 0x4d5a and

	pe.imports("wsock32.dll","WSAStartup") and
	pe.imports("wsock32.dll","socket")
}