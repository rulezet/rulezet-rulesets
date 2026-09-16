import "pe"
rule VeraCryptInstaller : IDRIX
{
	meta:
		author="_pusher_"
		date = "2016-03"
		description = "Installer"
	strings:
		$a0 = { 54 43 49 4E 53 54 52 54 01 }
	condition:
				$a0 at (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)
}