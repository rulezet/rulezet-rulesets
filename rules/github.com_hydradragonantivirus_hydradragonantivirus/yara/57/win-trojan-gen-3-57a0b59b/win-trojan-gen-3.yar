rule Win_Trojan_Gen_3
{
strings:
	$a0 = { 33c933d2cd21a128062d0500a32d01b440b90600ba2a01cd21b8024233c933d2cd2153a107 }


condition:
	$a0
}