rule Win_Trojan_Deviant_6
{
strings:
	$a0 = { b84403d1e88bc88b96b80447478b0533c28905e2f6 }


condition:
	$a0
}