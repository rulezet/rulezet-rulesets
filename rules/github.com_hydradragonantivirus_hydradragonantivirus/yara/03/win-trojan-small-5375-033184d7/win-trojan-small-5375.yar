rule Win_Trojan_Small_5375
{
strings:
	$a0 = { e8??000000(e9|e8)ad81f055bc1101e83d0000006639fe0f85dfffffff81c744f6ffffffe7 }


condition:
	$a0
}