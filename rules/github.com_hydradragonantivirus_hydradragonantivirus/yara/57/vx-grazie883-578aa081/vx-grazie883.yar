import "pe"
rule _Vx_Grazie883_
{
	meta:
		description = "Vx: Grazie.883"
	strings:
		$0 = {1E 0E 1F 50 06 BF 70 03 B4 1A BA 70 03 CD 21 B4 47 B2 00 BE 32 04 CD 21}
	condition:
		$0 at pe.entry_point
}