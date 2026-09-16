import "pe"
rule _UPX_071__072_PE_DLL_
{
	meta:
		description = "UPX 0.71 - 0.72 [PE DLL]"
	strings:
		$0 = {80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE EF 00 00 FF 57 66 81 87 00 00 00 00 00 00 81 C6 B1 01 00 00 EB 07 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE}
	condition:
		$0 at pe.entry_point
}