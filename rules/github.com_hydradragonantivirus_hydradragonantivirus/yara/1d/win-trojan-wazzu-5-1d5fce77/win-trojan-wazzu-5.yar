rule Win_Trojan_Wazzu_5
{
strings:
	$a0 = { 010100550004000000ffffe90700006902000004000000e907 }


condition:
	$a0
}