rule BlackEnergy2 : hardened
{
	meta:
		author = "CISA"
		source = "https://www.cisa.gov/sites/default/files/file_attach/ICS-ALERT-14-281-01E.yara"
		score = 60

	strings:
		$ex1 = {44 69 73 70 61 74 63 68 43 6f 6d 6d 61 6e 64}
		$ex2 = {44 69 73 70 61 74 63 68 45 76 65 6e 74}
		$a1 = {68 A1 B0 5C 72}
		$a2 = {68 6B 43 59 4E}
		$a3 = {68 E6 4B 59 4E}

	condition:
		all of ( $ex* ) and 3 of ( $a* )
}