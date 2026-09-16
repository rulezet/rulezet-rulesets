rule Win_Trojan_VGEN_592
{
strings:
	$a0 = { 4e01b409cd21b90a0051ba41010e1f33c9b43ccd21500e1f16580500108ec0be1903e89f005b061f33d28bcfb440cd }


condition:
	$a0
}