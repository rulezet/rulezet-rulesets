rule Win_Trojan_Bel_1
{
strings:
	$a0 = { bb0201cd2186fb3bc37502eb631e582d04008ec026 }


condition:
	$a0
}