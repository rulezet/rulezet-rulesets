rule Win_Trojan_Trojan_280
{
strings:
	$a0 = { 73000e5731c0509a64069b009ae7059b00bf66011e57bfa5000e5731c0509a64069b009ae7059b }


condition:
	$a0
}