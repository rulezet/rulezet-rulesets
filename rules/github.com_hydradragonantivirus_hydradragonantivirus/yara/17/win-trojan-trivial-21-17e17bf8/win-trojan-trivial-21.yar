rule Win_Trojan_Trivial_21
{
strings:
	$a0 = { 01cd217301c3b443b000ba9e00cd21b80143b100cd21b8013dcd2193b440b1379090ba0001cd }


condition:
	$a0
}