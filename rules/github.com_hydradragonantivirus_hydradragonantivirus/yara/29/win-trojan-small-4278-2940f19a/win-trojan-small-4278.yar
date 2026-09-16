rule Win_Trojan_Small_4278
{
strings:
	$a0 = { e9??0000006800100000[0-255]599160505b[0-8]31c96689cbe9??ffffff }


condition:
	$a0
}