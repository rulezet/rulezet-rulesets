rule Win_Trojan_Corporate_1
{
strings:
	$a0 = { ffffe88c0083eb76b44ae88400bb7500b448e87c002d10008ec0bf00018bf7b94907f2a41e }


condition:
	$a0
}