rule Win_Trojan_Gen_38
{
strings:
	$a0 = { cd21b900c8bb5d21891e4c00890e4e }


condition:
	$a0
}