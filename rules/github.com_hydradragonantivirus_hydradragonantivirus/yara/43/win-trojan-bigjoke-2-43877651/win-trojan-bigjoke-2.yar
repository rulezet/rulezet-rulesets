rule Win_Trojan_BigJoke_2
{
strings:
	$a0 = { 8befcd105db9ffff4983f90075fa4659e2dfe8aa0059e2 }


condition:
	$a0
}