rule Win_Trojan_Trojan_273
{
strings:
	$a0 = { b81100500e9cb113ba19000e1fff2e1500b44ccd21c0000000 }


condition:
	$a0
}