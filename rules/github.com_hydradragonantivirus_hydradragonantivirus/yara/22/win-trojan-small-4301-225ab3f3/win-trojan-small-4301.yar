rule Win_Trojan_Small_4301
{
strings:
	$a0 = { bb999bedfd81eb999badfd81e8891a2526058936272653[0-50]5b????ffffff6a006a006a006a }


condition:
	$a0
}