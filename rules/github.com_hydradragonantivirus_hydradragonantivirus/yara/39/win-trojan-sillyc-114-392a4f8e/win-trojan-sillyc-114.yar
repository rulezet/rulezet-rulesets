rule Win_Trojan_SillyC_114
{
strings:
	$a0 = { 83ef035757bf00015e81c6d8008beeb90300f3a45fb44eb927008bd781c2db00cd217202eb1990b8000150c3b43ecd }


condition:
	$a0
}