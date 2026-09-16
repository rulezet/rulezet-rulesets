rule Win_Trojan_Bizarre_2
{
strings:
	$a0 = { b089c0cd2feb000e1fc606e80a00e8d800b80012cd2ffec07508b430cd213c03 }


condition:
	$a0
}