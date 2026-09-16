rule Win_Trojan_DataMolester_1
{
strings:
	$a0 = { 01018a27bb02018a0786c40503008bf08a8c0301e8e401 }


condition:
	$a0
}