import "pe"
rule _PEArmor_046__China_Cracking_Group_
{
	meta:
		description = "PE-Armor 0.46 -> China Cracking Group"
	strings:
		$0 = {E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41}
	condition:
		$0 at pe.entry_point
}