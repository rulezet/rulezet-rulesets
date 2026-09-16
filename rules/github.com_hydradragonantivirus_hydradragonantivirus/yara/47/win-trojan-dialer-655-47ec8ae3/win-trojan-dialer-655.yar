rule Win_Trojan_Dialer_655
{
strings:
	$a0 = { 33ff8d85ecfaffff57506870e440006840e44000e80a0002a5 }


condition:
	$a0
}