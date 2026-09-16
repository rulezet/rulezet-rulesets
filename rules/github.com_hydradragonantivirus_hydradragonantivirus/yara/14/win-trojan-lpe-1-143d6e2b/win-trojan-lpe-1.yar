rule Win_Trojan_LPE_1
{
strings:
	$a0 = { 0301b8023d8d940301cd21508db46601bf0010b93400e80d00b4405bcd21b43ecd21b44ccd21 }


condition:
	$a0
}