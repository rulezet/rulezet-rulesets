rule Win_Trojan_SillyCOM_1
{
strings:
	$a0 = { 9090e800005d81ed07018d9e1e02ff374343ff37b41a8d962202cd21ccb44e8d961402cd217203eb0490e9b200b42fcd2133c08d771eac0ac075fb83ee04 }


condition:
	$a0
}