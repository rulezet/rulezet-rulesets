rule Win_Trojan_Wanderer_3
{
strings:
	$a0 = { 3c072c07b000e87302b040b91c00ba2c07e86dfdb80042595acd21b440b92c0733d2cd21b800 }


condition:
	$a0
}