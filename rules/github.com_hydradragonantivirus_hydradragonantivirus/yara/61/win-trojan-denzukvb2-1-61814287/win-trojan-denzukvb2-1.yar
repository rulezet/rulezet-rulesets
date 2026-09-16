rule Win_Trojan_DenZukVB2_1
{
strings:
	$a0 = { e4cd13720d33d2b92128bb007eb809 }


condition:
	$a0
}