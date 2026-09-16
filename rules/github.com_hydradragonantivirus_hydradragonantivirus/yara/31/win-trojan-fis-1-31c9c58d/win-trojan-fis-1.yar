rule Win_Trojan_Fis_1
{
strings:
	$a0 = { 6d757333c933d2b80042cd217268bafac7b90300b440cd21725c33c9ba9b21b80042cd217250bf }


condition:
	$a0
}