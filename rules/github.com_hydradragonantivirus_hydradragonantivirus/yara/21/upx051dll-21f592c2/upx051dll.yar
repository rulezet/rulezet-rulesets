import "pe"
rule upx051dll
{
	meta:
		author = "PEiD"
		description = "UPX 0.51 DLL -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 7D 01 00 00 60 E8 00 00 00 00 58 83 E8 48 50 8D B8 ?? ?? ?? ?? 57 8D B0 E0 01 00 00 83 CD FF 31 DB 90 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB }
	condition:
		$a0 at pe.entry_point
}