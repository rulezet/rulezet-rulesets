rule Win_Trojan_W_260
{
strings:
	$a0 = { 8d4424f833db648703e8000000005b8d4b445150500f014c24fe5b83c324fa8b2b668b6bfc8d71 }


condition:
	$a0
}