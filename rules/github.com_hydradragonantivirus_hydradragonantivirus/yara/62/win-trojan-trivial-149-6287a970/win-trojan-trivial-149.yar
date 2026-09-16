rule Win_Trojan_Trivial_149
{
strings:
	$a0 = { 01b44ecd21ba9e00b8013dcd218bd8b440b11fba0001cd21cc2a2e2a00 }


condition:
	$a0
}