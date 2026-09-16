rule Win_Trojan_DamnByte_2
{
strings:
	$a0 = { be0601bf0b01b90500f3a4 }


condition:
	$a0
}