rule Win_Trojan_W_351
{
strings:
	$a0 = { 7228897a2c8dbd1c050000b9350100004f4f4f4f31078b07e2f6eb1b520f014c24fe5a8b72288b7a2c5b66895a28c1eb }


condition:
	$a0
}