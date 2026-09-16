rule Win_Trojan_IVP_19
{
strings:
	$a0 = { 1901b934032e8a272e32a663042e882743e2f2c3 }


condition:
	$a0
}