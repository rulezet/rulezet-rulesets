rule Win_Trojan_Bishop_2
{
strings:
	$a0 = { 81ee5001b8cdab8b0c31d231c14801c08af58ad189144681fea51375ea8cd981c110008ec1 }


condition:
	$a0
}