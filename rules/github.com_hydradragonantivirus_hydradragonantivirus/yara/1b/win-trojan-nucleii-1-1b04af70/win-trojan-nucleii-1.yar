rule Win_Trojan_Nucleii_1
{
strings:
	$a0 = { e80f00ba00018b1ebc03b9b304b440cd21c3ba5c03b41acd }


condition:
	$a0
}