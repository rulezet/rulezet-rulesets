rule Win_Trojan_Pages_2
{
strings:
	$a0 = { 81ef030150535251061e33edb82135cd212e8c8554022e899d5202b81c35cd212e8c85ab022e899da9028cd8b92000 }


condition:
	$a0
}