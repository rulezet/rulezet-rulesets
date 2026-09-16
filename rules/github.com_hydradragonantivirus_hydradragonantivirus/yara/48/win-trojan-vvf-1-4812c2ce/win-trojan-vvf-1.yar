rule Win_Trojan_VVF_1
{
strings:
	$a0 = { 0681c300018bf3fcf3a41ebb000153cb8cd8488ed88b1e }


condition:
	$a0
}