rule Win_Trojan_VGEN_50
{
strings:
	$a0 = { b104d3e88ccb03c350b8140150cb8cd80e0e0e1f071750e80300cd20905efcad93ac5053e87601e8030032c0cf }


condition:
	$a0
}