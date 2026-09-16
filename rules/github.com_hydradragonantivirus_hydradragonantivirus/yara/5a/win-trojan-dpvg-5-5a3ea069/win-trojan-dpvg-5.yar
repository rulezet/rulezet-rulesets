rule Win_Trojan_DPVG_5
{
strings:
	$a0 = { 62792044756b652f534d469a00008d005589e581ec0001bfd5040e57bf52001e57b8ff00509a }


condition:
	$a0
}