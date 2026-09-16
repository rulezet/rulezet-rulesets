rule Win_Trojan_Whale_14
{
strings:
	$a0 = { d7ebf65a81ea9d23f987dab98a2cf8 }


condition:
	$a0
}