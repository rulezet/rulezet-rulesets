rule Win_Trojan_Vulcan_2
{
strings:
	$a0 = { cd213c937450b82135cd21891e1b028c061d020e5848 }


condition:
	$a0
}