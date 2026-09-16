rule Win_Trojan_SillyC_4
{
strings:
	$a0 = { 5c012bd98bf3bf0001b80a0050b8ffc250b8f63350b8a43350b857f35033c033db33d2ffe4 }


condition:
	$a0
}