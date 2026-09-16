rule Win_Trojan_Delyrium_1
{
strings:
	$a0 = { 81ee5705b9f20641f3a4b462cd21 }


condition:
	$a0
}