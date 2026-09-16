rule Win_Trojan_Int78_1
{
strings:
	$a0 = { 7403e95c012e8c162f022e892631028cc88ed0b8 }


condition:
	$a0
}