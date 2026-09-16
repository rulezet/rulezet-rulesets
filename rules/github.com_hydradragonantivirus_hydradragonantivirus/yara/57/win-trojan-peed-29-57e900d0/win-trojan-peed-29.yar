rule Win_Trojan_Peed_29
{
strings:
	$a0 = { 13c2d53b39a6fb08cafd78df60400b4f }


condition:
	$a0
}