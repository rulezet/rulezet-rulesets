rule _SoftComp_1x__BG_Soft_PT_
{
	meta:
		description = "SoftComp 1.x -> BG Soft PT"
	strings:
		$0 = {E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 8B 04 24 89 85 2A 0F 41 00 58 8B 85 2A 0F 41 00}
	condition:
		$0
}