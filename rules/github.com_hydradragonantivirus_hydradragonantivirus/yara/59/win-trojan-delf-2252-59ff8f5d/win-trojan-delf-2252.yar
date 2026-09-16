rule Win_Trojan_Delf_2252
{
strings:
	$a0 = { 558bec81c4f0feffff5356b88c202000e887f6ff }

	$a1 = { 0068656c6c6f }

	$a2 = { 1fa057682f2c2d3233303136d7343a }


condition:
	$a0 and $a1 and $a2
}