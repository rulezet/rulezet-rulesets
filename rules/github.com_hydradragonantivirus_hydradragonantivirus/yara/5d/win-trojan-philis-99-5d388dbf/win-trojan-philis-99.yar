rule Win_Trojan_Philis_99
{
strings:
	$a0 = { 56e8000000005e5e606033f761e800000000565781f64c1b }


condition:
	$a0
}