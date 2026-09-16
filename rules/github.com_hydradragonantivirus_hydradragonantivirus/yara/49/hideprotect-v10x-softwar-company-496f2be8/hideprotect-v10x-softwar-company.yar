import "pe"
rule _HideProtect_V10X_SoftWar_Company_
{
	meta:
		description = "Hide&Protect V1.0X-> SoftWar Company"
	condition:
		uint32(pe.entry_point) == 0x90909090 and
		uint32(pe.entry_point + 4) == 0x90909090 and
		uint32(pe.entry_point + 8) == 0x90909090 and
		uint32(pe.entry_point + 12) == 0x90909090 and
		uint32(pe.entry_point + 16) == 0x90909090 and
		uint32(pe.entry_point + 20) == 0x90909090 and
		uint32(pe.entry_point + 24) == 0x90909090
}