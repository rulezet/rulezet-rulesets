rule Win_Trojan_Gen_109
{
strings:
	$a0 = { 1001b932008a2480f4dd882446e2f6 }


condition:
	$a0
}