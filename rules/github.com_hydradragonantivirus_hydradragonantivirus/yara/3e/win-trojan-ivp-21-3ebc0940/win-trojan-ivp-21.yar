rule Win_Trojan_IVP_21
{
strings:
	$a0 = { 9e0e01b984012e8a272e32a692022e882743e2f2c3 }


condition:
	$a0
}