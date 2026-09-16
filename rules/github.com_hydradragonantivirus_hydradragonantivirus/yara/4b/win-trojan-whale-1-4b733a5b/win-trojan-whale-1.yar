rule Win_Trojan_Whale_1
{
strings:
	$a0 = { e8020045695a0e81eaa0231fb9d80b }


condition:
	$a0
}