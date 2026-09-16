rule Win_Trojan_Eumel_14
{
strings:
	$a0 = { 4559cd16b41aba64facd218db62e02bf0001b90300fcf3a4b419cd212ea27602b40eb202 }


condition:
	$a0
}