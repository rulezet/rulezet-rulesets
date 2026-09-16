rule Win_Trojan_Whale_5
{
strings:
	$a0 = { e828008ccb1e8edb5b81eb9f23e81e00 }


condition:
	$a0
}