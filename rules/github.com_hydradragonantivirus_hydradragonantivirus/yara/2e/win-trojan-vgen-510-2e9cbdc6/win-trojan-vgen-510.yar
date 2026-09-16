rule Win_Trojan_VGEN_510
{
strings:
	$a0 = { 218ec3263b1e160075308bda8a0750b42fcd2158fec0750383c307268a4717241f3c1e7515 }


condition:
	$a0
}