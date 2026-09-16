rule Win_Trojan_Pox_7
{
strings:
	$a0 = { 010100558e00000000ffff000000002c010000030000000103 }


condition:
	$a0
}