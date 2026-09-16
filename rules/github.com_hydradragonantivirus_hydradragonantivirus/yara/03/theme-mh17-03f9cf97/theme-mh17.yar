rule theme_MH17 {
	meta:
		author = "@tylabs"
		version = "1.0"
		date = "2014-04-09"
	strings:
		$callsign1 = "MH17" ascii wide nocase fullword
		$callsign2 = "MAS17" ascii wide nocase fullword
		$desc1 = "malaysia airlines flight 17" ascii wide nocase

	condition:
		any of them
}