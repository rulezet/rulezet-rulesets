rule Win_Trojan_Tula_5
{
strings:
	$a0 = { b80143cc72??b8023dcc72??930e0e1f07b80057cc5152 }


condition:
	$a0
}