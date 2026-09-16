rule mswin_ntlm_auth {
	meta:
		description = "Chinese Hacktool Set - file mswin_ntlm_auth.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "390af28581db224af38a885b7ffad819c9b3be89"
	strings:
		$s1 = "Login attempt had result %d" fullword ascii
		$s2 = "Username string exceeds %d bytes, rejecting" fullword ascii
		$s3 = "checking domain: '%s', user: '%s'" fullword ascii
		$s4 = "Usage: %s [-d] [-v] [-A|D LocalUserGroup] [-h]" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 380KB and all of them
}