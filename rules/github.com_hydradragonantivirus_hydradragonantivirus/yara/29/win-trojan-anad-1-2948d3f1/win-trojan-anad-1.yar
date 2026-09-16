rule Win_Trojan_Anad_1
{
strings:
	$a0 = { b4f1cd2181fba9ad74538cd8488ec026832e030030832e0200308e0602000e1f8bf531ffb9d502 }


condition:
	$a0
}