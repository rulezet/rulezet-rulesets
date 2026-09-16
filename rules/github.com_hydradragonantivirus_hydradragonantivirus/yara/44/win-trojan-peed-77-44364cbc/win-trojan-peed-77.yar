rule Win_Trojan_Peed_77
{
strings:
	$a0 = { ba8840420087d36a086a096a006a006a0c6a0d8d54 }


condition:
	$a0
}