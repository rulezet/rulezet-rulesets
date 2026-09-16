rule Win_Trojan_U_116
{
strings:
	$a0 = { 2dfeaffeaf5281ec1c1100005557565383c4fce9070200008d44242850ffb424 }


condition:
	$a0
}