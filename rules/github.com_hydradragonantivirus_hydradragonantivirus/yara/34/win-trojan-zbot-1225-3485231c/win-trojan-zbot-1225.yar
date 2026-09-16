rule Win_Trojan_Zbot_1225
{
strings:
	$a0 = { e91a0000000000efc8004d9aab0421f7a60400e60000000000000000b200abc1f20881f7dd50be }


condition:
	$a0
}