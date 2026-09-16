rule Win_Trojan_Pixel_26
{
strings:
	$a0 = { 5dbaf201b409cd21b405b200b600b5 }


condition:
	$a0
}