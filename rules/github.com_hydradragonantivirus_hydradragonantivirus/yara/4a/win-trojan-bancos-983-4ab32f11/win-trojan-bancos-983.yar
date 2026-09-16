rule Win_Trojan_Bancos_983
{
strings:
	$a0 = { 95d10311e77a89fab9aa2d4aee6d46a27083ee246bf46de981f2657c25ade92ffed393d39a192274a81a11afba38259be6ccd3c01a29e4195868baac7d3b49d0 }


condition:
	$a0
}