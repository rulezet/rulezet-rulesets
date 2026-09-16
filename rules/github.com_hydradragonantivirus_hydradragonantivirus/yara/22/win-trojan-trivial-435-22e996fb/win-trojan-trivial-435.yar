rule Win_Trojan_Trivial_435
{
strings:
	$a0 = { 33c9b80143cd21b8013dba9e00cd2193b440b95610ba0001cd21b43ecd21b44febc8b42acd21 }


condition:
	$a0
}