rule Win_Trojan_Peed_87
{
strings:
	$a0 = { 83c9ff41e836000000f7d029c74f4029c6eb4c5589e58d550c8b128b1292c9 }


condition:
	$a0
}