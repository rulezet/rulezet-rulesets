rule Win_Trojan_VGEN_42
{
strings:
	$a0 = { 909090e800005d81ed07018d9e1d02ff374343ff37b41a8d962102cd21ccb44e8d961302cd217202eb03e9b200b42f }


condition:
	$a0
}