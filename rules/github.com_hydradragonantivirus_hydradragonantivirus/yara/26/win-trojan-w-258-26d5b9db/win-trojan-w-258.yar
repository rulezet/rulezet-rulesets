rule Win_Trojan_W_258
{
strings:
	$a0 = { 4424f833db648703e8000000005b8d4b445150500f014c24fe5b83c32cfa8b2b668b6bfc8d71 }


condition:
	$a0
}