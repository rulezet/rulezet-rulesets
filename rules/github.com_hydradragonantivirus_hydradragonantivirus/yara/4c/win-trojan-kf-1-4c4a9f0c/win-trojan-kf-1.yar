rule Win_Trojan_KF_1
{
strings:
	$a0 = { 9506b80143e8d703b8023d8d969506e8cd0393b43fb91c008d965b06e8c0033e80be5b064d75 }


condition:
	$a0
}