rule Win_Trojan_Delf_1657
{
strings:
	$a0 = { e965f0ffffebe85f5e5b8be55dc3558bec538bd88bd3b8983f4000e862ffffff5b5dc3 }


condition:
	$a0
}