rule Win_Trojan_BAT_88
{
strings:
	$a0 = { 2f64656c657465206e657420757365205c5c }

	$a1 = { 2f64656c6574652064656c2072756e6d65 }

	$a2 = { 2e626174 }


condition:
	$a0 and $a1 and $a2
}