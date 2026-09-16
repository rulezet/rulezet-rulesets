rule Win_Trojan_Bandersnatch_1
{
strings:
	$a0 = { 1700be8c01022c55bf360f8a3fb90b00b0a88a342e280489db49462e904fbd110075ef90fd5993ac930138e9ae34 }


condition:
	$a0
}