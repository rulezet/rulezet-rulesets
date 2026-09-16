rule Win_Trojan_SIS_1
{
strings:
	$a0 = { da00b44033d2b94c09e8d0003bc1741b }


condition:
	$a0
}