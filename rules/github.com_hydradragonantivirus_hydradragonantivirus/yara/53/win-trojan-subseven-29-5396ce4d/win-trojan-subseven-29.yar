rule Win_Trojan_SubSeven_29
{
strings:
	$a0 = { 2dfd6ad0f102e44e91bb80fc95105a7f3e670421f614eebbe705363d9e3cab1f2944fd21dfd506aa1b55fb039cfd557262505d794ba1cead1ef193a20d0ce3fddb6454751fe9ec3710885abd1124 }


condition:
	$a0
}