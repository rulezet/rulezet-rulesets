rule Win_Trojan_DestructorV4_1
{
strings:
	$a0 = { e8cffd72cbe858ff2ec7460c00012e81660e00002e8166030000 }


condition:
	$a0
}