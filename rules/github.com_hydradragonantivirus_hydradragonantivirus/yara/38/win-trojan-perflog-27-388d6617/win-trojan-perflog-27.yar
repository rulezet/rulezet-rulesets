rule Win_Trojan_Perflog_27
{
strings:
	$a0 = { 7c1c33143509002000000062706b686b2e646c6cda6ef445d617722c70a448e48c2dcdc9 }


condition:
	$a0
}