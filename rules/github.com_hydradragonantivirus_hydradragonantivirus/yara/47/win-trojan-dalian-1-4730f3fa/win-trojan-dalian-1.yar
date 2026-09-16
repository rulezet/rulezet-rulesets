rule Win_Trojan_Dalian_1
{
strings:
	$a0 = { be40052ea08205fa83f900740c2e8a2432e02e88244649ebeffbc3e896ffe8dcffc3e8d8ff }


condition:
	$a0
}