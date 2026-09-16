rule Win_Trojan_VGEN_320
{
strings:
	$a0 = { ffeb0690b8004ccd21e2f6b44eb90700baa301cd217312909090b43b8d168201cd217220909090ebe2b8013dba9e }


condition:
	$a0
}