rule Win_Trojan_MiniB_1
{
strings:
	$a0 = { 0500105007e8b000be00018bfeb9c800fcf3a450b81b0150cb061e078d36c801bf0001b99c77f3a51fb41aba8000 }


condition:
	$a0
}