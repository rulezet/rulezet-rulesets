rule Win_Trojan_CodeBreaker_2
{
strings:
	$a0 = { 5d81ed0601b991008db6200189f7adf7d8350000f7d8abe2f5 }


condition:
	$a0
}