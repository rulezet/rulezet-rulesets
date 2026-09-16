rule Win_Trojan_Pluta_3
{
strings:
	$a0 = { 73617968656c6c6f203d[0-17]66696c652866696c652e7061746826222e68656c6c6f22 }


condition:
	$a0
}