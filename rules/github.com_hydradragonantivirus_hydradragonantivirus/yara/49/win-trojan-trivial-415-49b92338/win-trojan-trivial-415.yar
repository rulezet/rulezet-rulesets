rule Win_Trojan_Trivial_415
{
strings:
	$a0 = { fe061d01b43c32c9ba1d01cd2193b440b123ba0001cd21b43ecd21cd20 }


condition:
	$a0
}