rule Win_Trojan_VGEN_618
{
strings:
	$a0 = { 0d06b9410480055647497ff90769aaab359ea471eea811f12b26a811f1a51eaf0170af6d6d3518a8376029ab4e4f92 }


condition:
	$a0
}