rule Win_Trojan_Vienna_34
{
strings:
	$a0 = { 0105b9010033d2cd13eb2290b9140081c68300b4aa8ac432048ae024803c0075d6d0e4022446e2 }


condition:
	$a0
}