rule Win_Trojan_VB_1015
{
strings:
	$a0 = { 4f00700065006e }

	$a1 = { 66726d506f70706572 }

	$a2 = { 4475636b79 }


condition:
	$a0 and $a1 and $a2
}