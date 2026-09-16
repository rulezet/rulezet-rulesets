rule Win_Trojan_Vulcan_4
{
strings:
	$a0 = { cd213c93c306b82135cd21891ebe018c06c00158488e }


condition:
	$a0
}