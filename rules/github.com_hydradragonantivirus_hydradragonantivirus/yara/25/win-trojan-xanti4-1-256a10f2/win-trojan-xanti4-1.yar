rule Win_Trojan_XANTI4_1
{
strings:
	$a0 = { c686d10202b41a8d96a602cd21b82435cd21899ea2028c86 }


condition:
	$a0
}