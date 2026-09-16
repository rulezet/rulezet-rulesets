rule Win_Trojan_Eumel_21
{
strings:
	$a0 = { 5b81eb0a018bebb801faba4559cd16b41aba64facd218db63c02bf0001b90300fcf3a4b419cd212ea28402b40e }


condition:
	$a0
}