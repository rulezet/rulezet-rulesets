rule Win_Trojan_Sysxample_1
{
strings:
	$a0 = { 268b0e2301890e6800a32301b44033d2b91d01cd21b8004233c999cd21b440b90a00ba1d01cd21 }


condition:
	$a0
}