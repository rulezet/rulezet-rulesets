rule Win_Trojan_B_28
{
strings:
	$a0 = { 02b90100ba8000cd13721a26803fe87414b8010341cd1389dfb9ba01fcf3a4b8010341cd13b8 }


condition:
	$a0
}