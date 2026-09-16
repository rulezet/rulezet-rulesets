rule Win_Trojan_Tiny_72
{
strings:
	$a0 = { 02b440b904008d962002cd21b8024233c933d2cd21b440b928018d960001cd21b8002ccd21 }


condition:
	$a0
}