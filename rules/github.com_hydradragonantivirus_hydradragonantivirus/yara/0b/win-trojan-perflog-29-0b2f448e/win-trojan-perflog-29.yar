rule Win_Trojan_Perflog_29
{
strings:
	$a0 = { 2a8c43a621331d3509002000000062706b686b2e646c6c1601d5150c8915 }


condition:
	$a0
}