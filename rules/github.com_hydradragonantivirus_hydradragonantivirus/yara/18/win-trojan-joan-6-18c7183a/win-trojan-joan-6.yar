rule Win_Trojan_Joan_6
{
strings:
	$a0 = { 9cfc505351525657551e06e800005e83ee0e56b88818cd213d494d743fbbffffb44acd21b44a83eb32cd21 }


condition:
	$a0
}