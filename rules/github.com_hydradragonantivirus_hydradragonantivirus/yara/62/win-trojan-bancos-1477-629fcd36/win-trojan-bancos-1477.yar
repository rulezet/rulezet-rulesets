rule Win_Trojan_Bancos_1477
{
strings:
	$a0 = { e8f7feffff05a4320000ffe0e8ebfeffff0539a60000ffe0e804000000ffffffff }


condition:
	$a0
}