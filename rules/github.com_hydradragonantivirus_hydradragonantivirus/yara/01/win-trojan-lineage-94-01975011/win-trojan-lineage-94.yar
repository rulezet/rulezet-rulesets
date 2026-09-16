rule Win_Trojan_Lineage_94
{
strings:
	$a0 = { e6fe9436c1ff337a891481b457936e37625451e6fe2b96ee2c54e5ea8c2f9d05caa25e52be9270ac95cc6f8fb82d72ed7bfe8daee8a3c3f9ac915898730a58cb7e494b7c }


condition:
	$a0
}