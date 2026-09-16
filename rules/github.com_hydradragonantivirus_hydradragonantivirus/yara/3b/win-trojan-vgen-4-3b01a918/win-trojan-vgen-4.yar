rule Win_Trojan_Vgen_4
{
strings:
	$a0 = { ca2e89160d03b430cd218b2e02008b1e2c008edaa309178c060717891e0317892e1f17e81601c43e01178bc78bd8b9 }


condition:
	$a0
}