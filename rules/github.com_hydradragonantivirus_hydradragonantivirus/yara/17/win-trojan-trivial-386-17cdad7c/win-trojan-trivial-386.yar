rule Win_Trojan_Trivial_386
{
strings:
	$a0 = { cd217206b44fcd2172007221b8013dba9e00cd2193b440b148ba0001cd21b43ecd21b44f }


condition:
	$a0
}