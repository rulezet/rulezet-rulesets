rule Win_Trojan_Dikshev_44
{
strings:
	$a0 = { c9b43ccd2193b440ba5b02b93e0090cd21b43ecd21ba570233c9b43ccd2193b44033d2fe }


condition:
	$a0
}