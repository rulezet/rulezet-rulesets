rule Win_Trojan_Small_4286
{
strings:
	$a0 = { e9??000000[0-255]e8000000005991[0-255]60505b31c9 }


condition:
	$a0
}