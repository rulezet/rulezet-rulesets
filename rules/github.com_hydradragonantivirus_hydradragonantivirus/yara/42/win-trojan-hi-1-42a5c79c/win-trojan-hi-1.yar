rule Win_Trojan_Hi_1
{
strings:
	$a0 = { b80042cd21ba0800b90500b440cd21721f33c933d2b80242cd21b44033d2b97a01cd21b80157 }


condition:
	$a0
}