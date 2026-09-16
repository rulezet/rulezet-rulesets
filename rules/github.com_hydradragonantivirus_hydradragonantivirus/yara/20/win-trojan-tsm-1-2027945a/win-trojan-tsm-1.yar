rule Win_Trojan_TSM_1
{
strings:
	$a0 = { 2e89160d03b430cd218b2e02008b1e2c008edaa367148c066514891e6114892e7d14e81601c43e5f148bc78bd8b9 }


condition:
	$a0
}