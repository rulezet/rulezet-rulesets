rule Win_Trojan_Attack_2
{
strings:
	$a0 = { 8000ad3c04724732e48bc8ad3c41723e3c5a76083c6172363c7a773280fc3a752d24df2c418ad0b40ecd21b419cd }


condition:
	$a0
}