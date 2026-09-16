rule Win_Trojan_Trivial_131
{
strings:
	$a0 = { cd21b8023dba9e00cd2193b44083c262cd21c32a2e43 }


condition:
	$a0
}