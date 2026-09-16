rule Win_Trojan_IVP_6
{
strings:
	$a0 = { 01b925092e8a272e32a4550a2e882743e2f2c3 }


condition:
	$a0
}