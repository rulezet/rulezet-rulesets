import "pe"
rule _PCShrinker_v020__Virogen_
{
	meta:
		description = "PC-Shrinker v0.20 -> Virogen"
	strings:
		$0 = {E8 E8 01 00 00 60 01 AD B3 27 40 00 68}
	condition:
		$0 at pe.entry_point
}