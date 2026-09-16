rule Win_Trojan_Bancos_808
{
strings:
	$a0 = { e221e3bb457319d687693605e4c98ce4cad5e2afa2ba7e74047ac2bf589a4e2cb218143eab4512119e13e34359fadc40884e9fdecff571d4bf946ef00d78ada56133d41876edc5c48aca33a2687a040e3c40 }


condition:
	$a0
}