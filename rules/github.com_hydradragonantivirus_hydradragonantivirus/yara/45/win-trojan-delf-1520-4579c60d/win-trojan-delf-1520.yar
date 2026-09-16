rule Win_Trojan_Delf_1520
{
strings:
	$a0 = { 53568bf0684c9a00106aff6a00e896aaffff8bd8e857abffff3db7000000751353e812acffff53e854aaffff8bc6e8 }


condition:
	$a0
}