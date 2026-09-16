rule Win_Trojan_VGEN_342
{
strings:
	$a0 = { fcbb000153b8065dcd2196a80f7533c1e80404508cdf03c70e1f8ec026813f504b741f8bf38bfbb9f500f3a4061f }


condition:
	$a0
}