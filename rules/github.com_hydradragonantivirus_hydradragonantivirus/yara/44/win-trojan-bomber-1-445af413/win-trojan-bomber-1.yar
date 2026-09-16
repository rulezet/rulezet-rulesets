rule Win_Trojan_Bomber_1
{
strings:
	$a0 = { 20b8e0e0cd210c007402cd20e4400ac07502cd2058 }


condition:
	$a0
}