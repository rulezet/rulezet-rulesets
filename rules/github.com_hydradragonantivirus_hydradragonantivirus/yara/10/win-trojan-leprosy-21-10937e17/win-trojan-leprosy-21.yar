rule Win_Trojan_Leprosy_21
{
strings:
	$a0 = { 90568b1e5e0153e81300905bb9fa1490ba0001b44090cd21e802 }


condition:
	$a0
}