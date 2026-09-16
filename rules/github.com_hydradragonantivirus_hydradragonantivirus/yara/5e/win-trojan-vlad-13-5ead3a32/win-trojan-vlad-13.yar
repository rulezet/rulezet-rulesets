rule Win_Trojan_VLAD_13
{
strings:
	$a0 = { e800005e83ee050e5650bbffffb44acd2181eb900053068cdd03dd8ec32bffb92a0451560efcf32ea406b13051cb }


condition:
	$a0
}