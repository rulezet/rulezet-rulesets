import "pe"
rule _ACProtect_109__Risco_Software_
{
	meta:
		description = "ACProtect 1.09 -> Risco Software"
	strings:
		$0 = {60 E8 01 00 00 00 E8 83 C4 04 85 DF E8 01 00 00 00 76 83 04 24 06 C3 0F 81 02 00 00}
	condition:
		$0 at pe.entry_point
}