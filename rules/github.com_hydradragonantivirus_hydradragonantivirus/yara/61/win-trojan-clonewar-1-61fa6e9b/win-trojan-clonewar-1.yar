rule Win_Trojan_CloneWar_1
{
strings:
	$a0 = { f7038bdc83c30fb104d3ebb44acd21bf2c01be0d01b90c }


condition:
	$a0
}