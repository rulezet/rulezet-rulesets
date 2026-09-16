rule Win_Trojan_Small_4279
{
strings:
	$a0 = { e9??0000006800100000[0-255]599160505b31c96689cbe9??ffffff }


condition:
	$a0
}