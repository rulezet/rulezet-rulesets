rule Win_Trojan_USSR_28
{
strings:
	$a0 = { b20083e10f83c1058cc88ed833d2b80040cd217234 }


condition:
	$a0
}