rule Win_Trojan_Eumel_8
{
strings:
	$a0 = { 5b81eb0a018bebb801faba4559cd16b41aba64facd218db61602bf0001b90300fcf3a4b419cd212ea25e02b40e }


condition:
	$a0
}