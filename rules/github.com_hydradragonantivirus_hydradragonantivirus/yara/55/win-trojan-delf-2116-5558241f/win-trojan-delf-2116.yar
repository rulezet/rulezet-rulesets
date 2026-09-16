rule Win_Trojan_Delf_2116
{
strings:
	$a0 = { 363038303103347d2f59646964add0ff61626f2e6e6f2d69702eae8b0097adca06438f30 }


condition:
	$a0
}