rule Win_Trojan_Horse_6
{
strings:
	$a0 = { 12e83203268a1db81612e829035b83c711 }


condition:
	$a0
}