rule Win_Trojan_Cinderella_1
{
strings:
	$a0 = { 8603be8400bb4d02e82001bf8e03be }


condition:
	$a0
}