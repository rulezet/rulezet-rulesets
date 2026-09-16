rule Win_Trojan_Stoned_24
{
strings:
	$a0 = { b8007c8be0fb0e508bf02bffa113042d0200a31304b106d3e08ec0a3837cb89900a3817ca14c00a3 }


condition:
	$a0
}