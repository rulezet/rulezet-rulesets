rule Win_Trojan_VGEN_572
{
strings:
	$a0 = { 028d96aa031e0e1fb43cb90300cd21721093b440b941008d966903cd21b43ecd21e9dc01b879 }


condition:
	$a0
}