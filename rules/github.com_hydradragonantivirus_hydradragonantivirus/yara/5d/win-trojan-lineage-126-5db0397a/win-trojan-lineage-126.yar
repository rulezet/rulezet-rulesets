rule Win_Trojan_Lineage_126
{
strings:
	$a0 = { 5504369b3bb1af2432888cf9b7906bbbf3e42bec509d4c97ed7e79b13d96807fc26c6cda5990adfd54cc225b4730405a51d55cae5cf1632ace66f2b5b70be14acd }


condition:
	$a0
}