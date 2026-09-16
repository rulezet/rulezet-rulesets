rule _tmp_vawtrak_14_3ae {
	meta:
		description = "Auto-generated rule - file 14_3ae.dat"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "4153ff4da80c7ec5216cd65efde8766e7b448f70761ba26e45af902ed075f35b"
	strings:
		$s1 = "KERneL32.Dll" fullword ascii 
		$s2 = "ystem32\\xpsp3res.dll" fullword wide 
		$s3 = "http://www.bullguard.com0" fullword ascii 
		$s4 = "'GlobalSign TSA for MS Authenticode - G20" fullword ascii 
		$s5 = "attemperate" fullword ascii 
		$s6 = "dsethead" fullword ascii 
		$s7 = "horologe" fullword ascii 
		$s8 = "~s:\\c@" fullword ascii 
		$s9 = "supportless" fullword ascii 
		$s10 = "eebhgfahigppdgqbgdieqigepp" fullword ascii 
		$s11 = "cgaqgghcecfagpciapqpfgegpefdbb" fullword ascii 
		$s12 = "microseismometrograph" fullword ascii 
		$s13 = "acetmethylanilide" fullword ascii 
		$s14 = "zygomaticoauricularis" fullword ascii 
		$s15 = "sensorivasomotor" fullword ascii 
		$s16 = "osteogenetic" fullword ascii 
		$s17 = "extradural" fullword ascii 
		$s18 = "advancing" fullword ascii 
		$s19 = "motherliness" fullword ascii 
		$s20 = "epicheirema" fullword ascii 
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and ( 10 of ($s*) ) ) or ( all of them )
}