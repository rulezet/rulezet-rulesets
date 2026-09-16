rule Win_Trojan_VB_1723
{
strings:
	$a0 = { 68756d6a7a680034367d23322e0000000050 }


condition:
	$a0
}