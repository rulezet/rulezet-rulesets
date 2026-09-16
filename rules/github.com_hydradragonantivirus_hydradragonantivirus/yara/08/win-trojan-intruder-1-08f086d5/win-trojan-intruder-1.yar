rule Win_Trojan_Intruder_1
{
strings:
	$a0 = { e8cbffb9270533d28b1efe00b440cd21 }


condition:
	$a0
}