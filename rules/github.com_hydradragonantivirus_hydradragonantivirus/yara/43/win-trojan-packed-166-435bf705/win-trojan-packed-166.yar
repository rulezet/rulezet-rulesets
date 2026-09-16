rule Win_Trojan_Packed_166
{
strings:
	$a0 = { 686c6c00006863682e64686d73737754e8????000083c40c83f8027c0d66b94d }


condition:
	$a0
}