rule Win_Trojan_Peed_287
{
strings:
	$a0 = { e802000000cd2ec1e10f83c4047a00681e1301005981c118dc000081c11e1301 }


condition:
	$a0
}