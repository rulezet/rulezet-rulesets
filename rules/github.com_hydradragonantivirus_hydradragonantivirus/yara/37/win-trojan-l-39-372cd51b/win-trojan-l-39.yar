rule Win_Trojan_L_39
{
strings:
	$a0 = { 0301882f4381fb9c047ef159c3ba00018b1ee50153e8e0ff5bb96403b440cd2153 }


condition:
	$a0
}