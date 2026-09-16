rule Win_Trojan_Delf_1681
{
strings:
	$a0 = { 57494e4c4f474f4e }

	$a1 = { 5c4762506c7567696e5c24 }

	$a2 = { 4f4654574152455c4d4943524f }

	$a3 = { 5c43555252454e5456455253494f4e5c5255 }


condition:
	$a0 and $a1 and $a2 and $a3
}