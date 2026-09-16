rule Win_Trojan_Sentinel_2
{
strings:
	$a0 = { 30cd2186c43d1e03721db413cd2f }


condition:
	$a0
}