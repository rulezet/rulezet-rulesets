rule Win_Trojan_SAD_1
{
strings:
	$a0 = { 8ad0b405b101b500b600b010cd13b98000be8000bf7f }


condition:
	$a0
}