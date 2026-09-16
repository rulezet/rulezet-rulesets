rule Win_Trojan_VGEN_471
{
strings:
	$a0 = { 06f37d8b1ef37d8006b27e02e88dfeeb39b80300f606f77d04740140f7e6d1e82a26b27e8bd881fbff0173d38b9700 }


condition:
	$a0
}