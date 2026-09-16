rule logfile_daemon {
	meta:
		description = "Chinese Hacktool Set - file logfile-daemon.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "132a8f628109cda7eb58c91f1c5e5e626cbfd14a"
	strings:
		$s0 = "Error: usage: %s <logfile>" fullword ascii
		$s1 = "vBWSSSj" fullword ascii 
		$s2 = "t-Ht!Ht" fullword ascii 
		$s3 = "QSUVW3" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 260KB and all of them
}