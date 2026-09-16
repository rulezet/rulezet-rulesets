rule Win_Trojan_Eddie_3
{
strings:
	$a0 = { 3502b47980f439e87cfeb8004233c999e873feb47980f4 }


condition:
	$a0
}