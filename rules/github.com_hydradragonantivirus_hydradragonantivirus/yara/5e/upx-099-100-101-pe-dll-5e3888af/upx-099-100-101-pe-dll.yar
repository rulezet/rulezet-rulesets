import "pe"
rule _UPX_099__100__101_PE_DLL_
{
	meta:
		description = "UPX 0.99 / 1.00 - 1.01 [PE DLL]"
	strings:
		$0 = {80 7C 24 08 01 0F 85 00 00 00 00 60 BE AE 00 00 00 8D BE 52 00 00 FF 57 83 CD FF EB 0D 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC}
	condition:
		$0 at pe.entry_point
}