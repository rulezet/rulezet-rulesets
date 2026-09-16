rule Win_Trojan_Peed_114
{
strings:
	$a0 = { b887d61200e9ba00000068cbdfffff56e8a300000035 }


condition:
	$a0
}