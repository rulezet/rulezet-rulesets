rule Win_Trojan_Haxdoor_109
{
strings:
	$a0 = { 711e34005e73f826b651080e00afd30b3a20f4971401d4b2f9fbe36075d9ccf0e5bc078e20c98b3d1f5307ef6da24078ddeec5e22807c25dea46de90b9d5602e00db5e29 }


condition:
	$a0
}