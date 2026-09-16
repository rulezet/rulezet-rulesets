rule Win_Trojan_Rabbit_1
{
strings:
	$a0 = { b904008d962002cd2180be230256742fb8024233c933 }


condition:
	$a0
}