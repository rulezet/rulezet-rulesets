rule Win_Trojan_Ida_2
{
strings:
	$a0 = { ff7440b44033d28b0e1505061fe89600b440ba0001b9d305e88b00b449e886000e1fb80042e8 }


condition:
	$a0
}