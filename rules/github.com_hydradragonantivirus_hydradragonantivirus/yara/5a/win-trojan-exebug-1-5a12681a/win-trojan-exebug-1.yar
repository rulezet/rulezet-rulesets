rule Win_Trojan_ExeBug_1
{
strings:
	$a0 = { 04b10648a31304d3e08ec0a3867c }


condition:
	$a0
}