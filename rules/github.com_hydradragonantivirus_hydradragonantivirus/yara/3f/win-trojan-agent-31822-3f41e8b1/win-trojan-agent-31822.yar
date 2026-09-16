rule Win_Trojan_Agent_31822
{
strings:
	$a0 = { c7000000000083c00439d075f3ff3510d3400068b9d14000e8fb200000 }


condition:
	$a0
}