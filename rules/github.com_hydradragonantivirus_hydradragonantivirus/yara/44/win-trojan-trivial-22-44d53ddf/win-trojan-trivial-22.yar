rule Win_Trojan_Trivial_22
{
strings:
	$a0 = { 3401cd21b44fcd217301c3b80043ba9e00cd21b80143b100cd21b8013dcd2193b440b1389090ba }


condition:
	$a0
}