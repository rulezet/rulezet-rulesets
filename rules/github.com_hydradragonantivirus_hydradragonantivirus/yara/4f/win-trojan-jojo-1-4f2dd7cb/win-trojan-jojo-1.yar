rule Win_Trojan_Jojo_1
{
strings:
	$a0 = { 011e57b8d21031d252509afc085e00bf06011e57bf86011e57b80e005031c050509a94085e00 }


condition:
	$a0
}