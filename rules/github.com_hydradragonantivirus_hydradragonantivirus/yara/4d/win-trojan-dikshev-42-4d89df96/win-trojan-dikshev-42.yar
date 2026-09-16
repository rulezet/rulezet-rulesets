rule Win_Trojan_Dikshev_42
{
strings:
	$a0 = { 8c0233c9b43ccd2193b440ba4e02b93e00cd21b43ecd21ba4a0233c9b43ccd2193b44033d2fec6 }


condition:
	$a0
}