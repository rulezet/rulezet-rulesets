rule Win_Trojan_Silly_4
{
strings:
	$a0 = { 722025256220696e20282a2e622a2920646f20636f707920253020252562 }


condition:
	$a0
}