rule Win_Trojan_Whale_13
{
strings:
	$a0 = { 5b0e1fe82b009383eb1db9c3118a0728 }


condition:
	$a0
}