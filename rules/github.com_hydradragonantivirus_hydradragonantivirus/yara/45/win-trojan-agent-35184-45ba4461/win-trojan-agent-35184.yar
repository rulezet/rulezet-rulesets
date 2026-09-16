rule Win_Trojan_Agent_35184
{
strings:
	$a0 = { 9c90e8000000005e3aff498bfe81eeb210010040564b81c73800000084c36800000000 }


condition:
	$a0
}