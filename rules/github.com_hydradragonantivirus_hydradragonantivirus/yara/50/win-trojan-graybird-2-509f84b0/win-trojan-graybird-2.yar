rule Win_Trojan_Graybird_2
{
strings:
	$a0 = { 486f6f4b2e444c4c000000004765744b657900005365746b6579686f6f6b }


condition:
	$a0
}