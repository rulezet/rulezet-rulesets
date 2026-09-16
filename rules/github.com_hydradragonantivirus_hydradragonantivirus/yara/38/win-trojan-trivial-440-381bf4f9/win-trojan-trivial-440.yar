rule Win_Trojan_Trivial_440
{
strings:
	$a0 = { baf001cd21720c8bd8b440b9c800ba0001cd21cd20 }


condition:
	$a0
}