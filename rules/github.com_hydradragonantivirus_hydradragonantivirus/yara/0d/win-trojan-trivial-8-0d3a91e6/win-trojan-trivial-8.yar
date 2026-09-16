rule Win_Trojan_Trivial_8
{
strings:
	$a0 = { b44eba????cd217219b8013dba9e00cd21b43ecd21b409ba2901cd21b44fcd21 }


condition:
	$a0
}