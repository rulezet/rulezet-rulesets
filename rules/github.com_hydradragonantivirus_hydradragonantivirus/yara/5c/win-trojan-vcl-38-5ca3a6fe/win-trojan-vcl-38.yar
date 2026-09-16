rule Win_Trojan_VCL_38
{
strings:
	$a0 = { 0201b8014333c98d541ecd21b8023dcd2193b440b91105ba0001cd21b801578b4c168b5418 }


condition:
	$a0
}