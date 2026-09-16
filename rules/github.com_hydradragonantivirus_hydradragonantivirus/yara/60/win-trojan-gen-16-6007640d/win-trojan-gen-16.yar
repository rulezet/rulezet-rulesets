rule Win_Trojan_Gen_16
{
strings:
	$a0 = { 4e8db6f701ffb6fb018986fb0105020089048d96f101b90500b440cd218b1481c20301b9730690 }


condition:
	$a0
}