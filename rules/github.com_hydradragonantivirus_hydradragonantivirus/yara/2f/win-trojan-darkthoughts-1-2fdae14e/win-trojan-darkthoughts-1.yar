rule Win_Trojan_DarkThoughts_1
{
strings:
	$a0 = { 402e8b9eb711b90018ba0000e861fdb800422e8b9eb71133c933d2e852fdb4402e8b9eb711b9 }


condition:
	$a0
}