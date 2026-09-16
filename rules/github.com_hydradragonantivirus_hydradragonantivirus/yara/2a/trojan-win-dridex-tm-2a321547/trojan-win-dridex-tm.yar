rule trojan_win_dridex_TM {
	meta:
		description = "Rule to identify Dridex.TM"
		author = "hidd3ncod3s@gmail.com"
		date = "2016-01-09"
	strings:
		$s1 = "str" fullword ascii
		$s2 = "SVWATAUAWUH" fullword ascii
		$mv1 = {0F B6 [6] 0F B6 [6] 0F B6 [6] 0F B6 [6] 0F B7}
		$mv2 = {0F B6 [3] 0F B6 [3] 0F B6 [3] 0F B6 [3] 0F B7}

	condition:
		all of ($s*) and ($mv1 or $mv2)
}