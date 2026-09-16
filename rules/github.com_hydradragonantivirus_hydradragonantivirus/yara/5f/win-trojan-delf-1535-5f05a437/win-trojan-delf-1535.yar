rule Win_Trojan_Delf_1535
{
strings:
	$a0 = { 0b0000005261764d6f6e442e65786500ffffffff320000005a4f417c }


condition:
	$a0
}