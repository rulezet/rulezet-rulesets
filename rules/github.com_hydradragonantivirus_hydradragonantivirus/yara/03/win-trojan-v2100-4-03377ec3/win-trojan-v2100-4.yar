rule Win_Trojan_V2100_4
{
strings:
	$a0 = { a5a55e33d2b92408b440cd21721733c87517 }


condition:
	$a0
}