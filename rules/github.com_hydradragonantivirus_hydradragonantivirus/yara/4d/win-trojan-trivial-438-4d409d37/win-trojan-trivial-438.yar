rule Win_Trojan_Trivial_438
{
strings:
	$a0 = { d201cd21b44e33c9ba2801cd21b8023dbaf001cd21720c8bd8b440b9c800ba0001cd21cd20 }


condition:
	$a0
}