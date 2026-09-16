rule Win_Trojan_Dichotomy_1
{
strings:
	$a0 = { 8bdc8b2f81ed030044443e81be52035b44b41a8d96 }


condition:
	$a0
}