import "pe"
rule SafengineShielden2x
{
	meta:
		author="_pusher_"
		date = "2015-12"
	strings:
				$a0 = { E8 1C 00 00 00 53 61 66 65 6E 67 69 6E 65 20 53 68 69 65 6C 64 65 6E 20 76 32 2E }
	condition:
		($a0 in (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset..pe.sections[pe.section_index(pe.entry_point)].raw_data_offset+pe.sections[pe.section_index(pe.entry_point)].raw_data_size))
}