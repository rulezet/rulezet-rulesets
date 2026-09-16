rule Win_Trojan_Small_4088
{
strings:
	$a0 = { eb41cd2e8d88a59b2943014d00817500563400008d }


condition:
	$a0
}