rule Win_Spyware_WOW_14
{
strings:
	$a0 = { 558bec83c4f0b8a03c4000e800f8ffff68343d40006a006801001f00e843f9ffff85c0751f68443d40006a006801001f00e82ef9ffff85c0750ae821fbffffe884feffff }


condition:
	$a0
}