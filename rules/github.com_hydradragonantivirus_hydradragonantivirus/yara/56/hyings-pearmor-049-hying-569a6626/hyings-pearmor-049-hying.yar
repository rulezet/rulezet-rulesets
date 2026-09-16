import "pe"
rule _hyings_PEArmor_049__Hying_
{
	meta:
		description = "hying's PE-Armor 0.49 -> Hying"
	strings:
		$0 = {56 52 51 53 55 E8 15 01 00 00 32 ?? ?? 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}