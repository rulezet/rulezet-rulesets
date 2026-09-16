rule Win_Trojan_B_75
{
strings:
	$a0 = { eb0a0e582d20008ec0b801029303061c7c33d2f736187cfec28aea33d2 }


condition:
	$a0
}