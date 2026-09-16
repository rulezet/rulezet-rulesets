rule Win_Trojan_It_1
{
strings:
	$a0 = { 30018db6f102bf0001b90300fcf3a406b42fcd21899efb028c86fd02b41a }


condition:
	$a0
}