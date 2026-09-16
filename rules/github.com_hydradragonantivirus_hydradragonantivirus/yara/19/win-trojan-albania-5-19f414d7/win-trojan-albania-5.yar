rule Win_Trojan_Albania_5
{
strings:
	$a0 = { 018bd583ea08b440cd2133ffeb03 }


condition:
	$a0
}