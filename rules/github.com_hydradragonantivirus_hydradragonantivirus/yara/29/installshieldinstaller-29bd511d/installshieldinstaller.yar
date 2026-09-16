import "pe"
rule  InstallShieldInstaller
{
	meta:
		author="_pusher_"
		date = "2016-07"
	strings:
		$a0 = "InstallShield" wide ascii nocase
		$a1 = "InstallShield.Setup" wide ascii nocase
	condition:
				($a0 at (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)) 
		or
						$a1
}