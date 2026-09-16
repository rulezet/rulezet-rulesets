rule Win_Trojan_C_12
{
strings:
	$a0 = { e4cf8a144680f2fe7406b406cd213b }


condition:
	$a0
}