rule Win_Trojan_Mayberry_3
{
strings:
	$a0 = { 01beed002e812f000083c3024e75f5 }


condition:
	$a0
}