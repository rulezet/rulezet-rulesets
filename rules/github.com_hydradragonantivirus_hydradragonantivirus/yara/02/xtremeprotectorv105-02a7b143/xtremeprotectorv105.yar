import "pe"
rule XtremeProtectorv105
{
	condition:
		uint8(pe.entry_point) == 0xE9 and
		uint8(pe.entry_point + 2) == 0x00 and
		uint32(pe.entry_point + 4) == 0x00000000 and
		uint16(pe.entry_point + 8) == 0x0000 and
		uint8(pe.entry_point + 10) == 0x00
}