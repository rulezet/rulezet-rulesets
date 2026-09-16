rule Win_Trojan_Menuet_1
{
strings:
	$a0 = { 608b2d0c00000089ef6681c7fa01b001aa6683c71bb02031c9b10baae2fd31c0b03a89eb6681c3cf01cd40 }


condition:
	$a0
}