rule Win_Trojan_Ontario_3
{
strings:
	$a0 = { 40b9da0233d2cd21b80157bc1405 }


condition:
	$a0
}