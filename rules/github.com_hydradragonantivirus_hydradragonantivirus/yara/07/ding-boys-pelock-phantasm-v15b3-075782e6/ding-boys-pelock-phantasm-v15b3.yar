import "pe"
rule _Ding_Boys_PElock_Phantasm_v15b3_
{
	meta:
		description = "Ding Boy's PE-lock Phantasm v1.5b3"
	strings:
		$0 = {9C 55 57 56 52 51 53 9C FA E8 5D 81 ED 5B 53 40 B0 E8 5E 83 C6 11 B9 27 30 06 46 49 75}
	condition:
		$0 at pe.entry_point
}