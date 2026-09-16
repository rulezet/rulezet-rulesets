rule Win_Trojan_VGEN_692
{
strings:
	$a0 = { eb00e84b02e800005d81ed090150535152565755061eb8cdabcd2181fbcdab747d0e1f8cc1b80935cd212e8c86c4012e }


condition:
	$a0
}