rule Win_Trojan_R_70
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb16558be82be88bc55d0c0580cc03c0ef08c0e308cd16c38bee6866 }


condition:
	$a0
}