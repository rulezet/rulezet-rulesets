rule Win_Adware_Lop_131
{
strings:
	$a0 = { e800000000b88fd10c005b03c3ffe0 }


condition:
	$a0
}