rule Win_Trojan_Gen_197
{
strings:
	$a0 = { 2e89160d03b430cd218b2e02008b1e2c008edaa337268c063526891e3126892e4d26e81601c43e2f268bc78bd8b9 }


condition:
	$a0
}