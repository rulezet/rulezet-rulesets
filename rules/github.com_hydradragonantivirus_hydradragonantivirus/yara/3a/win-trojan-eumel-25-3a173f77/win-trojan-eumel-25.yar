rule Win_Trojan_Eumel_25
{
strings:
	$a0 = { 4559cd16b41aba64facd218db65402bf0001b90300fcf3a4b419cd212ea29c02b40eb202 }


condition:
	$a0
}