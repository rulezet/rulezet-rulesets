rule BlackEnergy3 : hardened
{
	meta:
		author = "CISA"
		source = "https://www.cisa.gov/sites/default/files/file_attach/ICS-ALERT-14-281-01E.yara"
		score = 60

	strings:
		$a1 = {4d 43 53 46 5f 43 6f 6e 66 69 67}
		$a2 = {4e 54 55 53 45 52 2e 4c 4f 47}
		$a3 = {6c 64 70 6c 67}
		$a4 = {75 6e 6c 70 6c 67}
		$a5 = {67 65 74 70}
		$a6 = {67 65 74 70 64}
		$a7 = {43 53 54 52}
		$a8 = {46 4f 4e 54 43 41 43 48 45 2e 44 41 54}

	condition:
		4 of them
}