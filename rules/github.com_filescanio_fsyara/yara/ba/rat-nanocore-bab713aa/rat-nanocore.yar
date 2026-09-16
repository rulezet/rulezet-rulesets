rule RAT_NanoCore : refined hardened
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects NanoCore RAT"
		reference = "http://malwareconfig.com/stats/NanoCore"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		vetted_family = "NanoCore"

	strings:
		$a = {4e 61 6e 6f 43 6f 72 65}
		$b = {43 6c 69 65 6e 74 50 6c 75 67 69 6e}
		$c = {50 72 6f 6a 65 63 74 44 61 74 61}
		$d = {44 45 53 43 72 79 70 74 6f}
		$e = {4b 65 65 70 41 6c 69 76 65}
		$f = {49 50 4e 45 54 52 4f 57}
		$g = {4c 6f 67 43 6c 69 65 6e 74 4d 65 73 73 61 67 65}
		$h = {7c 43 6c 69 65 6e 74 48 6f 73 74}
		$i = {67 65 74 5f 43 6f 6e 6e 65 63 74 65 64}
		$j = {23 3d 71}
		$key = {43 6f 24 cb 95 30 38 39}

	condition:
		9 of them
}