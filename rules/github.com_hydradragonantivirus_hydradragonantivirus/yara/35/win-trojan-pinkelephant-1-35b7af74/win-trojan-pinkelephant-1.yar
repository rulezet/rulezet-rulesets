rule Win_Trojan_PinkElephant_1
{
strings:
	$a0 = { 26a102002d0010a31e00bf7c04bedd01 }


condition:
	$a0
}