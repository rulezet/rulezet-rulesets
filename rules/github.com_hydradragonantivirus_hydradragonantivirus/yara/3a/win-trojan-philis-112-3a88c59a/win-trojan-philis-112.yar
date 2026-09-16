rule Win_Trojan_Philis_112
{
strings:
	$a0 = { 525058893424891c245159505083c404 }


condition:
	$a0
}