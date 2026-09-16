rule Win_Trojan_Peed_240
{
strings:
	$a0 = { 8d0567450300ba75e4280089c1714181e94432fe }


condition:
	$a0
}