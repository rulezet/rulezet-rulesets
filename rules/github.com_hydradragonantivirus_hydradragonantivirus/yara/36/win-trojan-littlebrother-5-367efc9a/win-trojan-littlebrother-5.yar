rule Win_Trojan_LittleBrother_5
{
strings:
	$a0 = { 03b844008ec0bf00018bf7b94101f3a48ed9be8400 }


condition:
	$a0
}