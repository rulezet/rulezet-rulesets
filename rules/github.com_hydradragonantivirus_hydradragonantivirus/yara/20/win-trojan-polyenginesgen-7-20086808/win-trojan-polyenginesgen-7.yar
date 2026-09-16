rule Win_Trojan_PolyEngineSGen_7
{
strings:
	$a0 = { 01b409cd21b90a0051ba44010e1f33c9b43ccd21500e1f16580500108ec0be7601b92e00e8a9005b061f33d28bcf }


condition:
	$a0
}