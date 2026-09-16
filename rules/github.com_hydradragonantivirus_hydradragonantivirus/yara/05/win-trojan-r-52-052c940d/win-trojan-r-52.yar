rule Win_Trojan_R_52
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0c518bcb2bd959b80503cd16c38bee68666658cd2181fb66667469 }


condition:
	$a0
}