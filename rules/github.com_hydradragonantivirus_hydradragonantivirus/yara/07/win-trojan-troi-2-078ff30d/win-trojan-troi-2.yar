rule Win_Trojan_Troi_2
{
strings:
	$a0 = { 57a5a4c32ac0cf9c80fcfc7504b0a59dcf80fc4b7403e9 }


condition:
	$a0
}