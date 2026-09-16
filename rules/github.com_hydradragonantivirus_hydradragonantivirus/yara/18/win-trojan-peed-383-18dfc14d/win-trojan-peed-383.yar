rule Win_Trojan_Peed_383
{
strings:
	$a0 = { 8d0438054e3300003d4e33000074263d24ff00007f1fb9713aed }


condition:
	$a0
}