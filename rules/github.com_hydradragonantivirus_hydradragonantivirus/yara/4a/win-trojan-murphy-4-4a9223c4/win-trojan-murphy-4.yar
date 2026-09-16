rule Win_Trojan_Murphy_4
{
strings:
	$a0 = { 1f81ee1304b9890541f3a4b462cd21 }


condition:
	$a0
}