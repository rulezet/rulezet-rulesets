rule Win_Trojan_Cascade_16
{
strings:
	$a0 = { 8b360001313600018dbf4d01be8206313d3135474e75f8 }


condition:
	$a0
}