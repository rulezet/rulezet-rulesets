rule Win_Trojan_BugHunter_4
{
strings:
	$a0 = { 8d960c02cd21b905008db6fa01bf0001f3a4b44eb907008d96f401cd217303e9af00b8014332 }


condition:
	$a0
}