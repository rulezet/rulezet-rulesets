rule Win_Trojan_Small_4119
{
strings:
	$a0 = { b8e4581413e893feffff6888130000e801e6ffff687c7614136a006814591413e820e6ffff50e822e6ffffa17c761413506a0068ff0f1f00e8d0e5ffff8bf06a00e8bfe5ffff }


condition:
	$a0
}