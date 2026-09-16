rule Win_Trojan_Hella_1
{
strings:
	$a0 = { 0fb745f8508b45ec50e852fcffff83c4086a00e8d0f6ffff83c404ff45f8ebc9ff45fce97bffffff908db426000000006899910408e88ef6ffff83c404eb41 }

	$a1 = { 636b65742e0a000021426144426f5921202048654c }


condition:
	$a0 and $a1
}