rule Win_Trojan_Y_4
{
strings:
	$a0 = { ffcd213d6606743bbb8000291e02008e0602008cc8488ed8a103002bc3a303000e1fbf0001b92f }


condition:
	$a0
}