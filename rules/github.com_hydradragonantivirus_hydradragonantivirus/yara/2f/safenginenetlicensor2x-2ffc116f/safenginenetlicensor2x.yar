import "pe"
rule SafengineNetLicensor2x
{
	meta:
		author="_pusher_"
		date = "2015-12"
	strings:
				$a0 = { E8 1F 00 00 00 53 61 66 65 6E 67 69 6E 65 20 4E 65 74 4C 69 63 65 6E 73 6F 72 20 76 32 2E }
	condition:
		($a0 in (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset..pe.sections[pe.section_index(pe.entry_point)].raw_data_offset+pe.sections[pe.section_index(pe.entry_point)].raw_data_size))
}