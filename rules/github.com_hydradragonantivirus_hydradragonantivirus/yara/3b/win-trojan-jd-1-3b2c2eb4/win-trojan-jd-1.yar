rule Win_Trojan_JD_1
{
strings:
	$a0 = { b81335cd2106530411cd210653b82425501e520e1fba }


condition:
	$a0
}