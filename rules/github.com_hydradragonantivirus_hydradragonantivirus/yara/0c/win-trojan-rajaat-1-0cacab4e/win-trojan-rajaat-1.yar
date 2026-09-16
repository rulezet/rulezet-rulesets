rule Win_Trojan_Rajaat_1
{
strings:
	$a0 = { 91b41abae2fccd21b44eba7e01cd217254b44ff606f8fc1f74f0b43dba00fdcd2193911e5880c41050501fb43f99 }


condition:
	$a0
}