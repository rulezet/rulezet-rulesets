rule Upx_193
{
	meta:
		author = "PEiD"
		description = "Upx 1.9x -> Markus & Laszlo"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 28 8B 1E 83 EE FC 11 DB 72 1F 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 EB 52 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 46 }
	condition:
		$a0
}