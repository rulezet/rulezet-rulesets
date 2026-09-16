rule Win_Trojan_VGEN_770
{
strings:
	$a0 = { 5256571e060e1f0e07be00018b84db00a308002dc60029f08984c400b42fcd21899cdd008c84df00b41a8d94f1 }


condition:
	$a0
}