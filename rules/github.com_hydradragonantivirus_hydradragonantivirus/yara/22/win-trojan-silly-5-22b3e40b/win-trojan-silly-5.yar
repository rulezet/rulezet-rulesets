rule Win_Trojan_Silly_5
{
strings:
	$a0 = { 6f722025256220696e20282a2e622a2920646f20636f7079202525622b2530 }


condition:
	$a0
}