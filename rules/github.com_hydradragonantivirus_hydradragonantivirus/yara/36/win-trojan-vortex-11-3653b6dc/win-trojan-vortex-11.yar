rule Win_Trojan_Vortex_11
{
strings:
	$a0 = { 2acd21929280fa0275efb500b405b6009292b280cd13fec5929280fd20e0edeaf0ffffffcf9c0e }


condition:
	$a0
}