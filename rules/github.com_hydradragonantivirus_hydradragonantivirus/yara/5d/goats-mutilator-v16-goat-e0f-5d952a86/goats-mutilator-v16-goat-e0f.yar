import "pe"
rule _Goats_Mutilator_V16__Goat_e0f_
{
	meta:
		description = "Goats Mutilator V1.6 -> Goat/_e0f"
	strings:
		$0 = {E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D}
	condition:
		$0 at pe.entry_point
}