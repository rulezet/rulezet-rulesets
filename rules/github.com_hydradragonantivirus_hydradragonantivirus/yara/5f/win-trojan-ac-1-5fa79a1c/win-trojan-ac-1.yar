rule Win_Trojan_AC_1
{
strings:
	$a0 = { 01b9b5008db75701568bfead33875501abe2f8c3 }


condition:
	$a0
}