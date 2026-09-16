rule Win_Trojan_Vecna_5
{
strings:
	$a0 = { 07b44eb90700ba8a01cd217227b8023dba9e00cd2193e8740072113c8a740d3ca0743eb8014233c9cd21ebeab4 }


condition:
	$a0
}