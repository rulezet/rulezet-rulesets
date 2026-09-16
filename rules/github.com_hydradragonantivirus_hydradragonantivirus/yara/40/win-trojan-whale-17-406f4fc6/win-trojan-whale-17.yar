rule Win_Trojan_Whale_17
{
strings:
	$a0 = { 1fe8230081eaa02389d3b9238486cd }


condition:
	$a0
}