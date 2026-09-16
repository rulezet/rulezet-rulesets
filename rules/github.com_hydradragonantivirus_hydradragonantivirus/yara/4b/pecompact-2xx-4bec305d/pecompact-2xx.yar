import "pe"
rule PECompact_2xx : Jeremy Collake {
	meta:
		author = "_pusher_"
		date = "2016-01"
		version = "0.2"
	strings:
								$c2 = { 56 FF D1 5A 58 03 43 08 8B F8 52 8B F0 8B 46 FC 83 C0 04 2B F0 89 56 08 8B 4B 0C 89 4E 14 FF D7 89 85 ?? ?? ?? ?? 8B F0 8B 4B 14 5A EB 0C 03 CA 68 00 80 00 00 6A 00 57 FF 11 8B C6 5A 5E 5F 59 5B 5D FF E0 }
		$c3 = { 56 FF D1 5A 58 03 43 08 8B F8 52 8B F0 8B 46 FC 83 C0 04 2B F0 89 56 08 8B 4B 0C 89 4E 14 FF D7 5A 33 C9 66 3B 4E 2A 75 12 8B F0 68 00 80 00 00 51 8B 4B 14 03 CA 57 FF 11 8B C6 5A 5E 5F 59 5B 5D FF E0 }
							condition:
				(
		(pe.number_of_sections==2) and
		($c2 in (pe.sections[0].raw_data_offset..pe.sections[1].raw_data_offset+pe.sections[1].raw_data_size)) or
		($c3 in (pe.sections[0].raw_data_offset..pe.sections[1].raw_data_offset+pe.sections[1].raw_data_size))
		)
}