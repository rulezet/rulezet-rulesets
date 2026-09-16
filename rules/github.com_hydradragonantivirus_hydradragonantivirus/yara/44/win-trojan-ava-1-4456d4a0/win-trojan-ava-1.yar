rule Win_Trojan_AVA_1
{
strings:
	$a0 = { 02a10d022b060102a33000a1ff01a32c00b4408b1ee901b92602ba0000cd217303eb2d90b8 }


condition:
	$a0
}