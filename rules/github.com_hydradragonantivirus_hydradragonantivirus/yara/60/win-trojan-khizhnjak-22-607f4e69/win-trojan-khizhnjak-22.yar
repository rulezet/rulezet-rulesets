rule Win_Trojan_Khizhnjak_22
{
strings:
	$a0 = { 40cd217226b90000ba00008b1eb302b000b442cd217214bab502b903008b1eb302b440cd217204 }


condition:
	$a0
}