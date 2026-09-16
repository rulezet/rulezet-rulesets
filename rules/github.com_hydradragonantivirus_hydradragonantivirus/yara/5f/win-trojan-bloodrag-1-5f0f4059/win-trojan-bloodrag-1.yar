rule Win_Trojan_Bloodrag_1
{
strings:
	$a0 = { b90300bab602cd21e82600b4408b0e6201ba0001cd21b440b90300bab902cd21595a80e1f0 }


condition:
	$a0
}