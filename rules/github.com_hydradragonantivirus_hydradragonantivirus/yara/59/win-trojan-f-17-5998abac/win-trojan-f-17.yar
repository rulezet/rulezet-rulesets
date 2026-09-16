rule Win_Trojan_F_17
{
strings:
	$a0 = { 33c08bc08ec0b841008bc02687060c008bc0508cc88bc02687060e00508bc0cc8bc0589d8bc0582687060e008bc0 }


condition:
	$a0
}