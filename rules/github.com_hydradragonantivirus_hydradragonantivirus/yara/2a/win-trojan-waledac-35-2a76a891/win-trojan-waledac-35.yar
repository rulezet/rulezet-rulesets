rule Win_Trojan_Waledac_35
{
strings:
	$a0 = { 0af812e166d3f10af966f7d312f2c1d704d2ebc1d70d2ad0e82412 }


condition:
	$a0
}