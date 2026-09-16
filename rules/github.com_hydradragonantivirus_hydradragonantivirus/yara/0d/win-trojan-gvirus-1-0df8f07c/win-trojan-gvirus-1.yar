rule Win_Trojan_Gvirus_1
{
strings:
	$a0 = { bf0000f3a481ec000406bf980057cb0e1f8e063c008b36 }


condition:
	$a0
}