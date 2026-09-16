rule Win_Trojan_Trojan_256
{
strings:
	$a0 = { 58feccb104d3e88ccb03c350b8140150cb8cd80e0e0e1f071750e80300cd20905efcad93ac5053e87601e8030032c0cf5ab82425cd2106b42fcd215806538ec0 }


condition:
	$a0
}