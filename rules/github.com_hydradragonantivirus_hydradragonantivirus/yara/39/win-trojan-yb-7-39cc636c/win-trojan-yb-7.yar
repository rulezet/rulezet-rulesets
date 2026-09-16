rule Win_Trojan_YB_7
{
strings:
	$a0 = { 83ee0356fc81c66101bf0001a5a55e8d946a01b41acd21e85900b41aba8000cd21e82f00e83400b9320051b409ba4a }


condition:
	$a0
}