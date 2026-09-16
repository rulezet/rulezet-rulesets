rule Win_Trojan_Eraser_6
{
strings:
	$a0 = { 457261736546696c6573 }

	$a1 = { 46756e6374696f6e }

	$a2 = { 46696c65546f4572617365 }

	$a3 = { 46696c65546f45726173652e70617468 }


condition:
	$a0 and $a1 and $a2 and $a3
}