rule Win_Trojan_Grog_37
{
strings:
	$a0 = { 3d61720d93626360b960e9ba0001b43fc333c05060c3 }


condition:
	$a0
}