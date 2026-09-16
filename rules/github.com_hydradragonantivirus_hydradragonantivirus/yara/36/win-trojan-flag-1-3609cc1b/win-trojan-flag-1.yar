rule Win_Trojan_Flag_1
{
strings:
	$a0 = { 4004b8007431b80103b90700ba8000cd13fc0e1fbe }


condition:
	$a0
}