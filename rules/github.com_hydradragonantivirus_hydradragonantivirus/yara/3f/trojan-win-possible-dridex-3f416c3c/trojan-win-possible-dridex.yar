rule trojan_win_possible_dridex {
	meta:
		description = "Possibly Dridex sample"
		author = "hidd3ncod3s@gmail.com"
		date = "2015-12-26"
	strings:
		$s1 = "str" fullword ascii
		$s2 = "SVWATAUAWUH" fullword ascii
		$s3 = {56 57 53 55 81 EC 80 00}
	condition:
		($s2 or $s3) and $s1
}