rule Win_Trojan_Small_4154
{
strings:
	$a0 = { e80b0000008d6d02454539ef7516eb24 }


condition:
	$a0
}