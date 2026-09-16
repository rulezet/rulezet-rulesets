rule Win_Trojan_Half_1
{
strings:
	$a0 = { 2e130403b90600d3e02d00108ec033c0bb007c8a470103d88c473c33c0cd13b80302bb00f6 }


condition:
	$a0
}