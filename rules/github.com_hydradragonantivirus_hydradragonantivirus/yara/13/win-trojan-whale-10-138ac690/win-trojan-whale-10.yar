rule Win_Trojan_Whale_10
{
strings:
	$a0 = { e8f8ff81c35ddcb9c1118b074343 }


condition:
	$a0
}