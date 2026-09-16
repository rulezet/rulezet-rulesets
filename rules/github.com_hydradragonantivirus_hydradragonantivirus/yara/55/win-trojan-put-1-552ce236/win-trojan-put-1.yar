rule Win_Trojan_Put_1
{
strings:
	$a0 = { a0000030044681fe830775f704138ae0a30000e90802 }


condition:
	$a0
}