rule Win_Trojan_Cmonster_1
{
strings:
	$a0 = { 436f6f6b6965204d6f6e737465722073657276657220656e67696e65 }

	$a1 = { 6b726e6c6b696c6c }


condition:
	$a0 and $a1
}