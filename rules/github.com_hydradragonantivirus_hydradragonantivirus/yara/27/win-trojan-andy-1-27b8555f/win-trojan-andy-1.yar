rule Win_Trojan_Andy_1
{
strings:
	$a0 = { b90300b440cd212e8b1ea40253b00233c933d2b442cd212e8e1eb90233d25bb9f803b440cd }


condition:
	$a0
}