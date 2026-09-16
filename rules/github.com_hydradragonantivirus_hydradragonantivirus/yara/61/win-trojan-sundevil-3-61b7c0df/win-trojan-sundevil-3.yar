rule Win_Trojan_Sundevil_3
{
strings:
	$a0 = { 50070e1f8bf533ffb9b302f3a41fbaa601b82125cd210e }


condition:
	$a0
}