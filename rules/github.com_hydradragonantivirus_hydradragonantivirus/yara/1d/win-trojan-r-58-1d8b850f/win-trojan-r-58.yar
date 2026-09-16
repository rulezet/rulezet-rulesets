rule Win_Trojan_R_58
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0e33db568bf02bc65e0d0503cd16c38beec1e01080cc660c66cd21 }


condition:
	$a0
}