rule Win_Trojan_BadBoy_5
{
strings:
	$a0 = { 060200bf0001be0001b90b00f3a6 }


condition:
	$a0
}