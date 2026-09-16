rule Win_Trojan_Whale_20
{
strings:
	$a0 = { e90700fe0743e2fbebe1e82200b98523 }


condition:
	$a0
}