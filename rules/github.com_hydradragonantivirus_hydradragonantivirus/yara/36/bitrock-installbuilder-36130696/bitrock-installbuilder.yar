import "pe"
rule BitRock_InstallBuilder : BitRock Inc
{
	meta:
		author="_pusher_"
		date = "2015-12"
	strings:
		$a0 = { 0E 00 00 00 2E 65 68 5F 66 72 61 6D 65 00 }
	condition:
					$a0 at (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)
}