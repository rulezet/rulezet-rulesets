rule Win_Trojan_Gloria_1
{
strings:
	$a0 = { 64ff33648923cce98b64240833db648f0383c404bf00404000b9ce0300008b07d1c883e819c1c002 }


condition:
	$a0
}