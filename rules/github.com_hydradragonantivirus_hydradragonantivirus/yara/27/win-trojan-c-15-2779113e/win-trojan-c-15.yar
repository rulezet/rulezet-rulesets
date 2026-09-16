rule Win_Trojan_C_15
{
strings:
	$a0 = { cd212d030089869c01b440b9ba008d960601cd21b800422bc999cd21b440b904008d969b01cd21 }


condition:
	$a0
}