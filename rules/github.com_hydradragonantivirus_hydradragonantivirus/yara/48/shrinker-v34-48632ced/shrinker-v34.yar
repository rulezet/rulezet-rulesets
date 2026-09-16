import "pe"
rule _Shrinker_v34_
{
	meta:
		description = "Shrinker v3.4"
	strings:
		$0 = {58 60 8B E8 55 33 F6 68 48 01 E8 49 01}
	condition:
		$0 at pe.entry_point
}