rule Win_Trojan_W13_5
{
strings:
	$a0 = { 1683e11e83f91e74ec817f1a00fa77e5817f1a100272 }


condition:
	$a0
}