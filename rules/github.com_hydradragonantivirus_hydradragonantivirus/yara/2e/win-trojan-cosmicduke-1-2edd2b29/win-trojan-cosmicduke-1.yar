rule Win_Trojan_CosmicDuke_1
{
strings:
	$a0 = { 4d6f7a696c6c612f352e30202857696e646f7773204e5420352e313b20727605883c3f693d00 }


condition:
	$a0
}