rule Win_Trojan_Madonna_1
{
strings:
	$a0 = { 4d61646f6e6e61 }

	$a1 = { 4a6164726171756572204b696c6c6572 }


condition:
	$a0 and $a1
}