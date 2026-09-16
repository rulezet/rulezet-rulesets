rule Win_Trojan__0112_0004_002_1
{
strings:
	$a0 = { 3a04be0600e8a90051b90300b440ba1e04cd21b44059ba3a04cd2132c0e83100ba1b04cd215a59 }


condition:
	$a0
}