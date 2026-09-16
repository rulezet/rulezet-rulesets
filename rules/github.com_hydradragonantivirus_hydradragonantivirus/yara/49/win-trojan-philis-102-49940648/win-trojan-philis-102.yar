rule Win_Trojan_Philis_102
{
strings:
	$a0 = { 7c037d01eb60eb00e800000000520f02d15a5ab8d400000050f7d85803c257d3cf5f5003 }


condition:
	$a0
}