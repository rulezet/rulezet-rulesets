rule Win_Trojan_3NOP_1
{
strings:
	$a0 = { 33c08ed88ed0bc007c8bf4fba1130448a31304b106d3e0 }


condition:
	$a0
}