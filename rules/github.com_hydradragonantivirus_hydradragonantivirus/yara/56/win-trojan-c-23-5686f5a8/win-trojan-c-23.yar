rule Win_Trojan_C_23
{
strings:
	$a0 = { dd03b800425b33c999e83300b4405a59e82c00b80157595a83c90fe82100b43ee81c00b40dcd21 }


condition:
	$a0
}