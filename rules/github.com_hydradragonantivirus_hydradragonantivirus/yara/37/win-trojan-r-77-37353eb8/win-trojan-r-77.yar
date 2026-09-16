rule Win_Trojan_R_77
{
strings:
	$a0 = { 0201e800008b2e0001bcfeff81ed0a01e81600eb265f07e80f00b440b991018d960401cd21e80100c38b861a018db6 }


condition:
	$a0
}