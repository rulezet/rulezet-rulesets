rule Win_Trojan_Trivial_245
{
strings:
	$a0 = { b44eb90000ba2401cd21b43db002ba9e00cd2193b440b92a00ba0001cd21b43ecd21 }


condition:
	$a0
}