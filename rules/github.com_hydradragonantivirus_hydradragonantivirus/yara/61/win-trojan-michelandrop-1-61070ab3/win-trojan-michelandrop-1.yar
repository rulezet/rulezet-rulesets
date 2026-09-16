rule Win_Trojan_Michelandrop_1
{
strings:
	$a0 = { b409ba7c05cd21e86400b409bab206cd2132c0b9010033d2bb7c03cd257303eb4390b409bad506cd2132c0b90100ba0b00bb7c03cd267303eb2a9083c402b409 }


condition:
	$a0
}