rule Win_Trojan_Wisp_2
{
strings:
	$a0 = { 2d72656d6f76656b797300002d696e7374616c6c6b797300[0-100]6d73686d61696c }


condition:
	$a0
}