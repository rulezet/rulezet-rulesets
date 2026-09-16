rule Win_Trojan_Peed_250
{
strings:
	$a0 = { bade74b40b85c287de7300b980ed010068ae }


condition:
	$a0
}