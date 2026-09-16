import "pe"
rule _PC_Shrinker_v071_
{
	meta:
		description = "PC Shrinker v0.71"
	strings:
		$0 = {55 50 E8 5D EB 01 E3 60 E8 03 D2 EB 0B 58 EB 01 48 40 EB}
	condition:
		$0 at pe.entry_point
}