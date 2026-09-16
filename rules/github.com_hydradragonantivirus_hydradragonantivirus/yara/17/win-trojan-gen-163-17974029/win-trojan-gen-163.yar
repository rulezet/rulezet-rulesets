rule Win_Trojan_Gen_163
{
strings:
	$a0 = { c0e61d46610657e19205fb5dc3affcebeebf130407268b057af1aff1b1ff7f06d3e848b10cd3 }


condition:
	$a0
}