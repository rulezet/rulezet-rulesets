rule Win_Trojan_Gen_72
{
strings:
	$a0 = { b42acd2181f9c407720880fe067203e9 }


condition:
	$a0
}