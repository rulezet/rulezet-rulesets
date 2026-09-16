rule Win_Trojan_DutchTiny_5
{
strings:
	$a0 = { cd21803c4d741db002e8200097b96300b440cd21b0 }


condition:
	$a0
}