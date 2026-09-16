rule RogueWin32FufelAVA
{
	meta:
		Description  = "Rogue.FufelAV.sm"
		ThreatLevel  = "5"
	strings:
		$ = "avp:buy" ascii wide
		$ = "avp:scan" ascii wide
		$ = "Protection software" ascii wide
		$ = "Invalid registration key!" ascii wide
		$ = "Unprotected mode request" ascii wide
		$ = "Are you sure want to continue in unprotected mode?" ascii wide
		$ = "I have serial key" ascii wide
		$ = "Continue unprotected" ascii wide
		$ = "trying to infect your files" ascii wide
		$ = "Your computer was attacked from" ascii wide
		$ = "Attack was blocked" ascii wide
		$ = "Please register product to block hackers attack" ascii wide
		$ = "Scanning completed. No threads found." ascii wide
		$ = "Scanning completed. Cleanup is required." ascii wide
		$ = "Warning! %d Infections found!" ascii wide
		$ = "Registered version" ascii wide
		$ = "Unregistered version (Please register)" ascii wide
		$ = "Cured" ascii wide
		$ = "Infected process" ascii wide
		$str_0 = "Sinergia Cleaner" ascii wide
		$str_1 = "Sinergia software.lnk" ascii wide
		
		$str_2 = "fufel-av-2.com" ascii wide
		$str_3 = "fufel-av.com" ascii wide
	condition:
		(3 of them) or (any of ($str_*))
}