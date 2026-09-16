rule Win_Trojan_Sparse_6
{
strings:
	$a0 = { b80103bb007cb9010033d2cd13b8004ccd21 }


condition:
	$a0
}