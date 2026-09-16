rule Win_Trojan_Peed_381
{
strings:
	$a0 = { 8d0438054e3300003d4e33000074243d24ff00007f }


condition:
	$a0
}