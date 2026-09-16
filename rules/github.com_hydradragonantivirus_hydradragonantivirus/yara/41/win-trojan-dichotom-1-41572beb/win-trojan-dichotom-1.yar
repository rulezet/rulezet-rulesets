rule Win_Trojan_Dichotom_1
{
strings:
	$a0 = { 8bdc8b2f81ed030044443e81be56035b44b41a8d966503cd21b44eb907008d96a800cd2172 }


condition:
	$a0
}