import "pe"
rule upx070dll
{
	meta:
		author = "PEiD"
		description = "UPX 0.70 DLL -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 99 01 00 00 60 E8 00 00 00 00 58 83 E8 48 50 8D B8 ?? ?? ?? ?? 57 66 81 87 00 00 00 00 00 00 8D B0 FC 01 00 00 83 CD FF 31 DB EB 0C }
	condition:
		$a0 at pe.entry_point
}