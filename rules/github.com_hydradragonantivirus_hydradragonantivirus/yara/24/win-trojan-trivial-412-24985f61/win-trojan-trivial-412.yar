rule Win_Trojan_Trivial_412
{
strings:
	$a0 = { 8a1e8000c687810000ba8200b8023dcd219387f2b440cd21c3 }


condition:
	$a0
}