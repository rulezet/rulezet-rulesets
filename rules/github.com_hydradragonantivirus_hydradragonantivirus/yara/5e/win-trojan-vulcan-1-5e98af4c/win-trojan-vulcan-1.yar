rule Win_Trojan_Vulcan_1
{
strings:
	$a0 = { cd213c937426b82135cd21891ed8018c06da01be0001 }


condition:
	$a0
}