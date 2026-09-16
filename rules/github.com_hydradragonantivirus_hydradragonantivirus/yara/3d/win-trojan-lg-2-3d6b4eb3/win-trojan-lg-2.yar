rule Win_Trojan_LG_2
{
strings:
	$a0 = { 3e8b869a01a300013e8a869c01a20201b8d0f1cd213dadde7505b80001ffe01e8cdb4b8edb8b1e030081eb01 }


condition:
	$a0
}