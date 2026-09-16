rule Win_Trojan_Trivial_34
{
strings:
	$a0 = { cd217305b8004ccd21b8023dba9e00cd21938bcd83e90ffecd83e90633d2fec6b440cd21b4 }


condition:
	$a0
}