rule Win_Trojan_Trivial_318
{
strings:
	$a0 = { 4eba3401cd21eb07b44fcd217301c3b80043ba9e00cd21b80143b100cd21b8013dcd2193b440b138ba0001cd21b43ecd21ebd5 }


condition:
	$a0
}