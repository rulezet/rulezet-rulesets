rule Win_Trojan_AUS1024B_1
{
strings:
	$a0 = { 13eb2152a1137c8b36187cd1e633d2f7f6485a88c5b10133dbb80302b6018a16907ccd138cc005 }


condition:
	$a0
}