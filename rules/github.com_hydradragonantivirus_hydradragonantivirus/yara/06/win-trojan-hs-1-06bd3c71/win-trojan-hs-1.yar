rule Win_Trojan_HS_1
{
strings:
	$a0 = { 0100b44033d2b9c504e832feb8004233c98b160b0081ea0001e822feb440ba4b00b90800e817fe }


condition:
	$a0
}