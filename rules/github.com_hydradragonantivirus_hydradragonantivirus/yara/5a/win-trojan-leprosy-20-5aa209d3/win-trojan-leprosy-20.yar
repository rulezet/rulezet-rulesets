rule Win_Trojan_Leprosy_20
{
strings:
	$a0 = { 5c90905e8b1e5f0153e81300905bb9fa1490ba0001b44090cd21e802 }


condition:
	$a0
}