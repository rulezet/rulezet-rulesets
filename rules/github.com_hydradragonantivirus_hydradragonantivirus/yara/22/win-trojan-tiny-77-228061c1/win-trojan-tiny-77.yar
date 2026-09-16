rule Win_Trojan_Tiny_77
{
strings:
	$a0 = { 6100b440cd21b000e81200c604e9897c01b440cd21b43ecd21b44febc3b4429933c9cd21 }


condition:
	$a0
}