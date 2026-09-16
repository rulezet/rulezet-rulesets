rule Win_Trojan_Peed_195
{
strings:
	$a0 = { e84900000068f094000068008abfff5af7da595289e689d45889f405 }


condition:
	$a0
}