import "pe"
rule _PC_Shrinker_v029_
{
	meta:
		description = "PC Shrinker v0.29"
	strings:
		$0 = {BD 01 AD E3 38 40 FF B5 DF 38}
	condition:
		$0 at pe.entry_point
}