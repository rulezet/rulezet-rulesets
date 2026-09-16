rule Win_Trojan_Soldier_4
{
strings:
	$a0 = { cd21f7d2f6c6087516b419cd21f7d233da8bca80e2018af28ad0b80605cd13b85aa5cd213da5 }


condition:
	$a0
}