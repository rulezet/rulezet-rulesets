import "pe"
rule _Program_Protector_XP_v10_
{
	meta:
		description = "Program Protector XP v1.0"
	strings:
		$0 = {50 60 29 C0 64 FF 30 E8 5D 83 ED 3C 89 E8 89 A5 14 2B 85 1C 89 85 1C 8D 85 27 03 50 8B 85 C0 0F 85 C0 8D BD 5B 03 8D B5 43}
	condition:
		$0 at pe.entry_point
}