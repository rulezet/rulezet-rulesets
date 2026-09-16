rule Win_Trojan_Twin_1
{
strings:
	$a0 = { 8c4c048c4c088c4c0cb8004b8d160f01 }


condition:
	$a0
}