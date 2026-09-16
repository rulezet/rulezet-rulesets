rule Win_Trojan_SSR150_2
{
strings:
	$a0 = { 06892e0100e81d00b440595a833cff750acce80b00b440b99600cc071f61ebbdb80242eb03 }


condition:
	$a0
}