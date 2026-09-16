rule Win_Trojan_Joker2_1
{
strings:
	$a0 = { 06c7000100f9cffe4a4f4b45522d3031 }


condition:
	$a0
}