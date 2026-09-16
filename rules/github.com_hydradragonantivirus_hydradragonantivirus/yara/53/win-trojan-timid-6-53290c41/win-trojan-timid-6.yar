rule Win_Trojan_Timid_6
{
strings:
	$a0 = { ff83c200b93f00b44ecd210ac0750be809007406b4 }


condition:
	$a0
}