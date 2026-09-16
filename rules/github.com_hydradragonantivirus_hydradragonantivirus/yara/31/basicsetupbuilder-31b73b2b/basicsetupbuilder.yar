import "pe"
rule  BasicSetupBuilder : Amma software
{
	meta:
		author="_pusher_"
		date = "2016-08"
		description = "www.ammasw.com"
	strings:
		$a0 = { 00 00 00 04 41 4D 4D 41 41 4D 4D 41 }
	condition:
				$a0 at (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)
}