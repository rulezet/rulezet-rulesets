rule Win_Trojan_Antichrist_1
{
strings:
	$a0 = { 8b8489fd2ea300012e8b848bfd2ea3 }


condition:
	$a0
}