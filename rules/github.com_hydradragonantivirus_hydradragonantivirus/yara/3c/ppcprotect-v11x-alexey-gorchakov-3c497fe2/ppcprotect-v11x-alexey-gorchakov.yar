import "pe"
rule _PPCPROTECT_V11X__Alexey_Gorchakov_
{
	meta:
		description = "PPC-PROTECT V1.1X -> Alexey Gorchakov"
	strings:
		$0 = {FF 5F 2D E9 20 00 9F E5 00 00 90 E5 18 00 8F E5 18 00 9F E5 00 00 90 E5 10 00 8F E5 01 00 A0 E3 00 00 00 EB 02 00 00 EA 04 F0 1F E5}
	condition:
		$0 at pe.entry_point
}