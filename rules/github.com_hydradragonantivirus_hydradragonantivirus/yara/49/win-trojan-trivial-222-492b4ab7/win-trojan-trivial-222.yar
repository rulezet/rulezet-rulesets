rule Win_Trojan_Trivial_222
{
strings:
	$a0 = { 2201cd21b8013dba9e00cd218bd8b440b128ba0001cd21b43ecd21cd202a2e43 }


condition:
	$a0
}