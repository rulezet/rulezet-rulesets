rule Win_Trojan_Macho_1
{
strings:
	$a0 = { 56be5900b9260890d1e98ae1 }


condition:
	$a0
}