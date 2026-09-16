rule Win_Trojan_Peed_239
{
strings:
	$a0 = { fff78bc9f7d75951455d84cbb80a8452 }


condition:
	$a0
}