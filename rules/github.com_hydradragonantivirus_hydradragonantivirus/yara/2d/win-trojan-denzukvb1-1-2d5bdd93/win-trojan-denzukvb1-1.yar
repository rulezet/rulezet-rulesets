rule Win_Trojan_DenZukVB1_1
{
strings:
	$a0 = { cd13720d33d2b92128bb007eb806 }


condition:
	$a0
}