rule Win_Trojan_Stryke_2
{
strings:
	$a0 = { 40ba0701cd2172af58fec4c1e804a3fa00b440ba0000b9070190cd21729932c0e80f007292b440 }


condition:
	$a0
}