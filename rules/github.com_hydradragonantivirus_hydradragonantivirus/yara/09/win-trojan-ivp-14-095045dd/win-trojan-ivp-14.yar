rule Win_Trojan_IVP_14
{
strings:
	$a0 = { 01b974022e8a272e32a498032e882743e2f2c3 }


condition:
	$a0
}