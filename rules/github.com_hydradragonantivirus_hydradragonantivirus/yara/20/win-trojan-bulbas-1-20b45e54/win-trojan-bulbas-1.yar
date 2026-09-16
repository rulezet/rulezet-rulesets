rule Win_Trojan_Bulbas_1
{
strings:
	$a0 = { 22633a5c77696e646f77735c77696e646f777373797374656d2e73797322 }

	$a1 = { 5c6d76627377652e766273 }


condition:
	$a0 and $a1
}