rule Win_Trojan_Khizhnjak_31
{
strings:
	$a0 = { 022ea20001a0d0022ea20101a0d1022ea20201b90001bb00002e8a078887d30243e2f6bab302b92000b44ecd2173 }


condition:
	$a0
}