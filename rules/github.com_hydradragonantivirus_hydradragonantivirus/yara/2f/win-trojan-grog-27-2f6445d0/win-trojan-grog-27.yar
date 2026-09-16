rule Win_Trojan_Grog_27
{
strings:
	$a0 = { baf6d6cd218bd8b43fb90300bafd00cd21803efd00 }


condition:
	$a0
}