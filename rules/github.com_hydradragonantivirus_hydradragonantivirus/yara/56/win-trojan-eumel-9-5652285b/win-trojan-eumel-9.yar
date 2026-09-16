rule Win_Trojan_Eumel_9
{
strings:
	$a0 = { 5d939381ed0a01b801faba4559cd16b41aba64facd218db62802bf0001b90300fcf3a4b419cd212ea27002b40e }


condition:
	$a0
}