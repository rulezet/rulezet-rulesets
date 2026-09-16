rule Win_Trojan_Path_2
{
strings:
	$a0 = { 578a0788054347e2f8c605005fb80143cd21b8023d }


condition:
	$a0
}