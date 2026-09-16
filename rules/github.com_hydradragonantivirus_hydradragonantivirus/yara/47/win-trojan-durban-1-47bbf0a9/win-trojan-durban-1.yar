rule Win_Trojan_Durban_1
{
strings:
	$a0 = { 1100a4e2fdb4decd2180fcdf7447c6 }


condition:
	$a0
}