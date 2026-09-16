rule Win_Trojan_Joan_5
{
strings:
	$a0 = { 505351525657551e06e800005e83ee0e56b88818cd213d494d743fb44abbffffcd21b44a83eb32cd21722f33ff83 }


condition:
	$a0
}