rule Win_Trojan_Ash_1
{
strings:
	$a0 = { 0200eb213e8a8646078db63501b90f063004d2c046e2f9 }


condition:
	$a0
}