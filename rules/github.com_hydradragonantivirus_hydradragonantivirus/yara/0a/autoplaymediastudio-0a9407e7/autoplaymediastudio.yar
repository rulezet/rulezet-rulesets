import "pe"
rule  AutoPlayMediaStudio : IndigoRose
{
	meta:
		author="_pusher_"
		date = "2015-12"
		description = "Installer"
	strings:
				$a0 = { 50 4B 03 04 14 00 01 00 08 00 48 A2 CD 3A 2B E9 92 C3 A4 25 08 00 10 25 08 00 11 00 00 00 41 75 74 6F 50 6C 61 79 2F }
		$a1 = { 50 4B 05 06 5A 69 70 41 72 63 68 69 76 65 20 4D 61 70 70 69 6E 67 20 46 69 6C 65 }
		$a2 = { 0B 0B AF AF 0B 0B BF 00 00 00 }

	condition:
		$a0 and $a1 and
				$a2 at (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)
}