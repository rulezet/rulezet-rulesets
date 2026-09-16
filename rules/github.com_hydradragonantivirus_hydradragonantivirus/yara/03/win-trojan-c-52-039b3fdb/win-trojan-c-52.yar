rule Win_Trojan_C_52
{
strings:
	$a0 = { cd21723a93b92702ba0001b440cd21b43ecd21ba5b02 }


condition:
	$a0
}