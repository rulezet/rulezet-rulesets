rule Win_Trojan_Bljec_2
{
strings:
	$a0 = { b98000be7fffbf8000f3a4b8f3a4a3f9 }


condition:
	$a0
}