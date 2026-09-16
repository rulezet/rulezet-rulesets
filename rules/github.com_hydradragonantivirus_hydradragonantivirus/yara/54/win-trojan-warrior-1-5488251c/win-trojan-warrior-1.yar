rule Win_Trojan_Warrior_1
{
strings:
	$a0 = { 8032e403f826803501e2f3b419cd }


condition:
	$a0
}