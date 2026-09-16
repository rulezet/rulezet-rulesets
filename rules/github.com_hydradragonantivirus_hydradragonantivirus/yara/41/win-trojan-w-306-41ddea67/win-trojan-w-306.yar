rule Win_Trojan_W_306
{
strings:
	$a0 = { 24f833db648703e8000000005b8d4b519090905150500f014c24fe5b83c32cfa8b2b668b6b }


condition:
	$a0
}