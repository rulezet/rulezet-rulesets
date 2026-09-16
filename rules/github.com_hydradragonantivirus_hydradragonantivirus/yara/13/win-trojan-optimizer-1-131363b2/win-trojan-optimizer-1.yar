rule Win_Trojan_Optimizer_1
{
strings:
	$a0 = { 6f7527726520646561642e9a000052005589e5b800019acd02520081ec0001bf06031e579add05 }


condition:
	$a0
}