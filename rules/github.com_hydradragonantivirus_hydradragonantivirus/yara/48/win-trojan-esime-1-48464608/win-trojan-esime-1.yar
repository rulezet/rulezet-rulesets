rule Win_Trojan_Esime_1
{
strings:
	$a0 = { 167f01b97b01ba0000b440cd21b8004233d233c9cd }


condition:
	$a0
}