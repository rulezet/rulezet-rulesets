rule Win_Trojan_Xolominer_1
{
strings:
	$a0 = { 2a2a2a20586f6c6f6d696e6572202d205072696d65636f696e20506f6f6c204d696e6572 }


condition:
	$a0
}