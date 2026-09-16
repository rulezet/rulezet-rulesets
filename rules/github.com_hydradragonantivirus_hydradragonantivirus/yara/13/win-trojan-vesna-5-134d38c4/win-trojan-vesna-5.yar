rule Win_Trojan_Vesna_5
{
strings:
	$a0 = { cd213c03730ae8c505e87200071f61cb8a26e006cd21891e9201ba4c078a26df06cd21ba }


condition:
	$a0
}