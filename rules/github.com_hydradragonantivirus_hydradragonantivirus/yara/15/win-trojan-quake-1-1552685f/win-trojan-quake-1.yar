rule Win_Trojan_Quake_1
{
strings:
	$a0 = { 81ed07018db61e01b9d4012e8134000083c602e2f6 }


condition:
	$a0
}