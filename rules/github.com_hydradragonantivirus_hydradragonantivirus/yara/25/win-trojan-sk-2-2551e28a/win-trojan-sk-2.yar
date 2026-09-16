rule Win_Trojan_SK_2
{
strings:
	$a0 = { cd2180fa157511b80903ba0000b901008d1e0001cd13 }


condition:
	$a0
}