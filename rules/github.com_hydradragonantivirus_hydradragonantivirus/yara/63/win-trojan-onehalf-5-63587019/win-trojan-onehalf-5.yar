rule Win_Trojan_OneHalf_5
{
strings:
	$a0 = { 32d8c66b66c0d125a5b6f28c69b3d9ee5e476bf7aaea5fb7ea4b2970c12e34df9ab548beac694dcc6e28962ef0d47ed9 }


condition:
	$a0
}