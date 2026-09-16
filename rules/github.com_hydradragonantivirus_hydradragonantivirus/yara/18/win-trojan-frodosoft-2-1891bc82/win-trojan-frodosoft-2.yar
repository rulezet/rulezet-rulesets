rule Win_Trojan_FrodoSoft_2
{
strings:
	$a0 = { 03018bd8fcb903008db74a01bf0001f3a4538d97 }


condition:
	$a0
}