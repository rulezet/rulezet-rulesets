rule Win_Trojan_RingWorm_1
{
strings:
	$a0 = { 0602ffd0918ec026c70604000002268c0e060026c7060c000302268c0e0e000e07b802ca32dbcd2ffaf7dcf7dcfbb1 }


condition:
	$a0
}