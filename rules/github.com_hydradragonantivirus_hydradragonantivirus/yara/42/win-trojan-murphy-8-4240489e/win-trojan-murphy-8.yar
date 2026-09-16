rule Win_Trojan_Murphy_8
{
strings:
	$a0 = { 1f81ee8305b92b0741f3a4b462cd21 }


condition:
	$a0
}