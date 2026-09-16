rule Win_Trojan_Whale_30
{
strings:
	$a0 = { 0100f85b81eb9f23b523b185e81900 }


condition:
	$a0
}