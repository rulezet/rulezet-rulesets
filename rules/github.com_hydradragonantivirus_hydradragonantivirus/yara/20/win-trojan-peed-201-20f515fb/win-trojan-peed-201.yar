rule Win_Trojan_Peed_201
{
strings:
	$a0 = { e84?00000089e?c70???2901006800??bfff5af7da89d65952ad05 }


condition:
	$a0
}