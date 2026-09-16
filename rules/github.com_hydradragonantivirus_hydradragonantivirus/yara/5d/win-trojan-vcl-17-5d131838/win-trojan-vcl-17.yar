rule Win_Trojan_VCL_17
{
strings:
	$a0 = { e80701b44eb92700ba1d02cd217271e80b007504b44febf3b8014ccd21b8023dba9e00cd2193b42acd21983d0100742fb43fb90200ba5f01cd21813e5f01 }


condition:
	$a0
}