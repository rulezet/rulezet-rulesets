rule Win_Trojan_VGEN_610
{
strings:
	$a0 = { 91b41abae2fccd21b44eba7c01cd217252b44ff606f8fc1f74f0b43dba00fdcd2193911e5880c41050501fb43f99 }


condition:
	$a0
}