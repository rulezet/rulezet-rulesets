rule Win_Trojan_Horse_1
{
strings:
	$a0 = { 2012e87202268a1db81612e869025b83c711 }


condition:
	$a0
}