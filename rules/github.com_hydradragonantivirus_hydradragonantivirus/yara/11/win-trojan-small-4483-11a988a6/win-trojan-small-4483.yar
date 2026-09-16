rule Win_Trojan_Small_4483
{
strings:
	$a0 = { 5589e568??324200e817000000e81d000000ad01d035????????8946fc39f375ec5d }


condition:
	$a0
}