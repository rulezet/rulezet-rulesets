rule Win_Trojan_Trivial_33
{
strings:
	$a0 = { 43b000ba9e00cd21b443b001ba9e00b100cd21b8013dba9e00cd2193b440b1409090ba0001cd }


condition:
	$a0
}