rule Win_Trojan_B_23
{
strings:
	$a0 = { 017222b43c2e8b163e0233c9e83b0172148bd853b440ba3f0cb92900e82b015bb43ee82501c3 }


condition:
	$a0
}