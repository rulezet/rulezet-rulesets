rule Win_Trojan_SillyC_52
{
strings:
	$a0 = { 2c002bc13e8986a601b4408d960701b99f00cd2133c0e81500b4408d96a501cd215a59b80157cd }


condition:
	$a0
}