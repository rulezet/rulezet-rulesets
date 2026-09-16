rule Win_Trojan_Intar_2
{
strings:
	$a0 = { e8000000008b2c2481ed0620400083c4048db5272040008bfeb9170700008a06ac3400aae2f8 }


condition:
	$a0
}