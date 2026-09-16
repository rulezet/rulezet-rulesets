rule Win_Trojan_SK_1
{
strings:
	$a0 = { b800008ed88a2e08038a160903b1010e1fb80103b600 }


condition:
	$a0
}