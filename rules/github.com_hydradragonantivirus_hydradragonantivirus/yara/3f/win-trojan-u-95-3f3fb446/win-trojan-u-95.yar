rule Win_Trojan_U_95
{
strings:
	$a0 = { 74497984a59ab2415b82afd93079d4e28381abcdb559cab2a8a7b4753d0a28215babe6b9b4453d0c }


condition:
	$a0
}