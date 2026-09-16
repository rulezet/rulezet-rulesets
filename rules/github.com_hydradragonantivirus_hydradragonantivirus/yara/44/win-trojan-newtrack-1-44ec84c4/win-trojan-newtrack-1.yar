rule Win_Trojan_Newtrack_1
{
strings:
	$a0 = { c181f9080276f133c0cd13b80805bb7001b9015033d2cd13b80103bb0001b901502bd2cd13b81e }


condition:
	$a0
}