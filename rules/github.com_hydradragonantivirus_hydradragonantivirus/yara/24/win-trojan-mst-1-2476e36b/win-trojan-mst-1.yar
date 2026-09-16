rule Win_Trojan_Mst_1
{
strings:
	$a0 = { ba8000b90100cd13cd20209f20ace1e2ee202120 }


condition:
	$a0
}