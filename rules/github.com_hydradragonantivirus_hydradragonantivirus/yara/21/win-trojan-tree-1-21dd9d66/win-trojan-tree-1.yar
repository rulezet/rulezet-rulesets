rule Win_Trojan_Tree_1
{
strings:
	$a0 = { 02745bf6c2807556501e31c08ed8 }


condition:
	$a0
}