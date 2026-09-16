rule Win_Trojan_Trivial_565
{
strings:
	$a0 = { b9c4008a0534??880547e2f7 }


condition:
	$a0
}