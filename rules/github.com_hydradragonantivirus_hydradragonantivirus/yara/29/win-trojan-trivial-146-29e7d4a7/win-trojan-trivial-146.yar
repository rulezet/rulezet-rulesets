rule Win_Trojan_Trivial_146
{
strings:
	$a0 = { b120ba1b01cd21b8013dba9e00cd2193b44049ba0001cd21c32a2e2a00 }


condition:
	$a0
}