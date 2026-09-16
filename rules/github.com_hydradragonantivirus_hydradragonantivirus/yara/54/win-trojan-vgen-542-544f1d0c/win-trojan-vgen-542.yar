rule Win_Trojan_VGEN_542
{
strings:
	$a0 = { 06e8d8017353e824020e0732c0b9b400bfb305fcf3aae85d01b452e8820253b430e87c025fe894013c02722d3c03 }


condition:
	$a0
}