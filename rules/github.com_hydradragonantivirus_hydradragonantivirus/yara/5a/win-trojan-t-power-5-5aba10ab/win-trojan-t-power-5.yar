rule Win_Trojan_T_Power_5
{
strings:
	$a0 = { 02b4428b1e941433c933d2cdd4c332c0ebefb4408b1e9414cdd4c3b435cd21c3b425cdd4c3b4 }


condition:
	$a0
}