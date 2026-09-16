rule Win_Trojan_Pages_1
{
strings:
	$a0 = { 81ef030150535251061e33edb82135cd212e8c8554022e899d5202b81c35cd212e8c859d022e899d9b028cd8b91b00 }


condition:
	$a0
}