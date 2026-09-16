rule Win_Trojan_DamnByte_1
{
strings:
	$a0 = { 0801bf0c0133c9b104f3a4 }


condition:
	$a0
}