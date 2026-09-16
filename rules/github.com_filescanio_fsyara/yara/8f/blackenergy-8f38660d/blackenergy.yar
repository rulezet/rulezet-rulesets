rule BlackEnergy : hardened
{
	meta:
		author = "CISA"
		source = "https://www.cisa.gov/sites/default/files/file_attach/ICS-ALERT-14-281-01E.yara"
		score = 60

	strings:
		$hc1 = {68 97 04 81 1D 6A 01}
		$hc2 = {68 A8 06 B0 3B 6A 02}
		$hc3 = {68 14 06 F5 33 6A 01}
		$hc4 = {68 AF 02 91 AB 6A 01}
		$hc5 = {68 8A 86 39 56 6A 02}
		$hc6 = {68 19 2B 90 95 6A 01}
		$hc7 = {(68 | B?) 11 05 90 23}
		$hc8 = {(68 | B?) EB 05 4A 2F}
		$hc9 = {(68 | B?) B7 05 57 2A}

	condition:
		2 of ( $hc* )
}