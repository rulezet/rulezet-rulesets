rule Win_Trojan_Kashu_1
{
strings:
	$a0 = { 60e800000000????fecaeb019c8bf5[0-20]ffc6f30fb7d9 }


condition:
	$a0
}