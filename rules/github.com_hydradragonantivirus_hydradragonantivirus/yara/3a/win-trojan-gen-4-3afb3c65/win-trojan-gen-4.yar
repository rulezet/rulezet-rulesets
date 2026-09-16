rule Win_Trojan_Gen_4
{
strings:
	$a0 = { 0301891619040e07b91804bf3a04be0600e8a90051b90300b440ba1e04cd21b44059ba3a04cd }


condition:
	$a0
}