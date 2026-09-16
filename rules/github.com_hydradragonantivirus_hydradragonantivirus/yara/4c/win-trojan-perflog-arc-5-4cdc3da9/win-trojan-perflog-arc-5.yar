rule Win_Trojan_Perflog_arc_5
{
strings:
	$a0 = { 52617021 }

	$a1 = { 62706b686b2e646c6cade2 }


condition:
	$a0 and $a1
}