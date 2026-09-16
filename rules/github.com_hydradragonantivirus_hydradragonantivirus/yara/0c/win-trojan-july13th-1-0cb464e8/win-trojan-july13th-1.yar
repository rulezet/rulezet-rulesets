rule Win_Trojan_July13th_1
{
strings:
	$a0 = { 2ea012003490be1200b9b1042e300446 }


condition:
	$a0
}