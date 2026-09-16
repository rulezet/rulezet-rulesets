rule Win_Trojan_Something_5
{
strings:
	$a0 = { 8d3600018d3e0001b99202fcf3a48c06 }


condition:
	$a0
}