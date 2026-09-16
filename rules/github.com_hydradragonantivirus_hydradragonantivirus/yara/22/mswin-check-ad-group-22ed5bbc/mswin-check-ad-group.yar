rule mswin_check_ad_group {
	meta:
		description = "Chinese Hacktool Set - file mswin_check_ad_group.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "15fa3d91c5e4836f27b9809d4efedc5a947fb221"
	strings:
		$s1 = "Domain Global group mode enabled using '%s' as default domain." fullword ascii
		$s2 = "Warning: running in case insensitive mode !!!" fullword ascii
		$s3 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
		$s4 = "Windows group: %S, Squid group: %S" fullword ascii
		$s5 = "%s[%d]: " fullword ascii
		$s6 = "DC Active Directory Site is %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 380KB and 4 of them
}