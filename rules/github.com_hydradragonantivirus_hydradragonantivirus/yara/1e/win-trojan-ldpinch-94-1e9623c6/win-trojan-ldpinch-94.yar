rule Win_Trojan_LdPinch_94
{
strings:
	$a0 = { feb162e448a7597394dcb0f6b5b4cb93cc5156e8e523b223677b10b04b30baeeb20d35ea40edb25f4c2a944e4cf65885d4df51ef816e2626c2c3fef35ecb9fb95966d7b0761853b805cc29441ae4a871 }


condition:
	$a0
}