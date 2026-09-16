rule Win_Trojan_Trivial_342
{
strings:
	$a0 = { 4eba4001cd21b443b000ba9e00cd21b443b001ba9e00b100cd21b8013dba9e00cd2193b440b1449090ba0001cd21b43ecd21b44fcd2173ceb431ba3075cd21 }


condition:
	$a0
}