rule Win_Trojan_PS_10
{
strings:
	$a0 = { e800005b81eb0301bf00018db7????b90300f3a4b8ff4b33f633ffcd2181ffaa557505bb0001ffe3 }


condition:
	$a0
}