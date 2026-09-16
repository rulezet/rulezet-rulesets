rule Win_Trojan_Peed_305
{
strings:
	$a0 = { e80300000089e3cc5eb9fe960100ba04040040c1c20c89d652ad05 }


condition:
	$a0
}