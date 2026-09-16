rule Win_Trojan_Virut_212
{
strings:
	$a0 = { 90e81e00000053b9990c00008b }


condition:
	$a0
}