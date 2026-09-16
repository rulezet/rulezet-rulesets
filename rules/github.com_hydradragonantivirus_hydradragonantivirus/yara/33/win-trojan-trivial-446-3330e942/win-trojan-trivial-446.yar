rule Win_Trojan_Trivial_446
{
strings:
	$a0 = { ba4d01cd213d1200741cb8023dba9e00cd218bd8b440b9bc02ba0001cd21b43ecd21b44feb }


condition:
	$a0
}