rule Win_Trojan_Experimental_1
{
strings:
	$a0 = { 03008a0408c0740ab40ebb0100cd1046ebf030e4cd1608c074f831d2b90100b8010331dbcd13 }


condition:
	$a0
}