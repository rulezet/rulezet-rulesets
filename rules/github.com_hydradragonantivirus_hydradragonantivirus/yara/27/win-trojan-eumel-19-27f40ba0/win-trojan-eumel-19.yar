rule Win_Trojan_Eumel_19
{
strings:
	$a0 = { 5d939381ed0a01b801faba4559cd16b41aba64facd218db63c02bf0001b90300fcf3a4b419cd212ea28402b40e }


condition:
	$a0
}