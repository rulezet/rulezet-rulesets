rule Win_Trojan_Trakia_3
{
strings:
	$a0 = { 3dcd21930e1fb43fba3602b91800cd2133c933d2b802 }


condition:
	$a0
}