rule Win_Trojan_Search_6
{
strings:
	$a0 = { 5e0eb90f01b000300743e2fb }


condition:
	$a0
}