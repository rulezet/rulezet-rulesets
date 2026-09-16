rule Win_Trojan_EVC_5
{
strings:
	$a0 = { 81ef3edf81c73e6687f787f16a005acd21b873512d112605a0166a0059baa20081c2dbb281 }


condition:
	$a0
}