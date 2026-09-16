rule Win_Trojan_Gen_13
{
strings:
	$a0 = { b94e005651f3a4be0702b90500f3a4595e41f3a4b440ba0001e85500c3b95b01cd21be0501 }


condition:
	$a0
}