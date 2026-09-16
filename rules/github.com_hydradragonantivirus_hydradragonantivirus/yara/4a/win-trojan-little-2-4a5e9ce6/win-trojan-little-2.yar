rule Win_Trojan_Little_2
{
strings:
	$a0 = { f6b80fffcd213d01017415b44eb92700ba8c01cd217215e81d007504b44febf3b409ba9201cd21b8014ccd21fab40299b90001cd26ebfeb8014333c9ba9e00 }


condition:
	$a0
}