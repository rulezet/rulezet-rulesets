rule BlackEnergy2_Driver : hardened
{
	meta:
		author = "CISA"
		source = "https://www.cisa.gov/sites/default/files/file_attach/ICS-ALERT-14-281-01E.yara"
		score = 60

	strings:
		$a1 = {7E 4B 54 1A}
		$a2 = {E0 3C 96 A2}
		$a3 = {49 6f 66 43 6f 6d 70 6c 65 74 65 52 65 71 75 65 73 74}
		$b1 = {31 A1 44 BC}
		$b2 = {49 6f 41 74 74 61 63 68 44 65 76 69 63 65 54 6f 44 65 76 69 63 65 53 74 61 63 6b}
		$b3 = {4b 65 49 6e 73 65 72 74 51 75 65 75 65 44 70 63}
		$c1 = {A3 41 FD 66}
		$c2 = {61 1E 4E F8}
		$c3 = {50 73 43 72 65 61 74 65 53 79 73 74 65 6d 54 68 72 65 61 64}

	condition:
		all of ( $a* ) and 3 of ( $b* , $c* )
}