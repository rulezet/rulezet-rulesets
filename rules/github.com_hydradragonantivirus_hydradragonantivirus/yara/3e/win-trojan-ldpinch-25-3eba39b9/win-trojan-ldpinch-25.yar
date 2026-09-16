rule Win_Trojan_Ldpinch_25
{
strings:
	$a0 = { 558bec83c4f0b83c6a4000e810dcffff33c05568ad6a400064ff30648920e895fcffff33c05a595964 }


condition:
	$a0
}