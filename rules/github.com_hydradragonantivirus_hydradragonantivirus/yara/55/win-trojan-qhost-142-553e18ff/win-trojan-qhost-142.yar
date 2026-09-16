rule Win_Trojan_Qhost_142
{
strings:
	$a0 = { 558becb90d0000006a006a004975f9535657b8207b4000e898b9ffff33c05568 }


condition:
	$a0
}