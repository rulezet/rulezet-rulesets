import "pe"
rule trojan_win_dridex {
	meta:
		description = "Rule to identify Dridex(Dec 2015)"
		author = "hidd3ncod3s@gmail.com"
		date = "2015-12-26"
	strings:
		$s1 = "str" fullword ascii
		$s2 = "mod4" fullword ascii
		$s3 = "list" fullword ascii
		$s4 = "bot" fullword ascii
		$s5 = "mod5" fullword ascii
		$s6 = "SVWATAUAWUH" fullword ascii
		
	condition:
		pe.sections[5].name == ".sdata" and all of ($s*)
}