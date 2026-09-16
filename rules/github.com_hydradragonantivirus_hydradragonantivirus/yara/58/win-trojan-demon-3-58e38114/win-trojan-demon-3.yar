rule Win_Trojan_Demon_3
{
strings:
	$a0 = { fe06be01803ebe010a740275e5b409 }


condition:
	$a0
}