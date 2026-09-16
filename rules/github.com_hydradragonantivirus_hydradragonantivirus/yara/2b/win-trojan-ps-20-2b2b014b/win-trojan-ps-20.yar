rule Win_Trojan_PS_20
{
strings:
	$a0 = { cd21b8023dcd2193b440b903008d96cd01cd21b002e8 }


condition:
	$a0
}