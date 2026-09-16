rule Win_Trojan_FormatC_6
{
strings:
	$a0 = { 05b280b600cd1380c50180fd1075f0cd19 }


condition:
	$a0
}