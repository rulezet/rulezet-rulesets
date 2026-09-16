rule Win_Trojan_April_1st_2
{
strings:
	$a0 = { bf0001bee804b900ff81e9e804b4ddcd21eb3d900c07780a7604e207000181100000d8048713dc6e0000800031 }


condition:
	$a0
}