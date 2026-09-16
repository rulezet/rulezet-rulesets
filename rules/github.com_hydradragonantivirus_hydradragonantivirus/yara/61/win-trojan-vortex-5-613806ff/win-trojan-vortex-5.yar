rule Win_Trojan_Vortex_5
{
strings:
	$a0 = { 2acd21929280fa0575ef9292b500b405b6009292b280cd13fec5929280fd20e0ed0d0232000302 }


condition:
	$a0
}