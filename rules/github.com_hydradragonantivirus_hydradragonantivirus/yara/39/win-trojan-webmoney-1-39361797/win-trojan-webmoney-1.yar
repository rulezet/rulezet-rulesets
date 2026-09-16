rule Win_Trojan_WebMoney_1
{
strings:
	$a0 = { 8b008b15fc0c4500e8f31dffff8b0dc83a4500a1d43945008b008b156c0a4500e8db1dffffa1d43945008b00e84f1effffe87a1efbff0000ffffffff0e0000005765624d6f6e657920437261636b }


condition:
	$a0
}