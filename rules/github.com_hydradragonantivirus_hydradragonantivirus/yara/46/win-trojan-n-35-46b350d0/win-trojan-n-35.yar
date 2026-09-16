rule Win_Trojan_N_35
{
strings:
	$a0 = { e800005e81ee0d01e80500e98500000050535152b98d018bee81c65c048bfefdad33861801abe2f8 }


condition:
	$a0
}