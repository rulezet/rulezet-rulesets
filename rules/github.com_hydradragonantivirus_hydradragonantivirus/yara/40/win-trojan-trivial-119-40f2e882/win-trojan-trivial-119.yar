rule Win_Trojan_Trivial_119
{
strings:
	$a0 = { b44eba1701cd21b8013dba9e00cd2193b44087cacd21c3 }


condition:
	$a0
}