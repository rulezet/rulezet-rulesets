rule Win_Trojan_Illness_1
{
strings:
	$a0 = { 83ea2033ff3e8a86f3043e28831a01473bfa75 }


condition:
	$a0
}