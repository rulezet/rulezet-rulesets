rule Win_Trojan_Zorm_14
{
strings:
	$a0 = { b000b90b001e521fb43ebb41004bfecccd2104111fbb2500e86302 }


condition:
	$a0
}