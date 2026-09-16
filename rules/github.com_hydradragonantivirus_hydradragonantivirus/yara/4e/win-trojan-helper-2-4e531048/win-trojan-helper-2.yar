rule Win_Trojan_Helper_2
{
strings:
	$a0 = { 010100558e00000000ffff000000009c010000040000000103 }


condition:
	$a0
}