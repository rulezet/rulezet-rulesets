rule Win_Trojan_Flat_1
{
strings:
	$a0 = { fab8455992cd1687da87da87da2eff3638010e1f2eff2636010000 }


condition:
	$a0
}