import "pe"
rule _PCShrinker_v071__Virogen_
{
	meta:
		description = "PC-Shrinker v0.71 -> Virogen"
	strings:
		$0 = {9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 50 50 2D ?? ?? ?? 00 89 85}
	condition:
		$0 at pe.entry_point
}