rule Win_Trojan_SK_4
{
strings:
	$a0 = { 030089862702b440b93d018d960601cd21b8004233c933d2cd21b440b904008d962602cd21fe86 }


condition:
	$a0
}