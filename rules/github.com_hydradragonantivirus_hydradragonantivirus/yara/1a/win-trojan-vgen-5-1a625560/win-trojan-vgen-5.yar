rule Win_Trojan_Vgen_5
{
strings:
	$a0 = { 89160d03b430cd218b2e02008b1e2c008edaa359178c065717891e5317892e6f17e81601c43e51178bc78bd8b9 }


condition:
	$a0
}