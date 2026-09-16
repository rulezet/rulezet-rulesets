rule Win_Trojan_B_59
{
strings:
	$a0 = { 7a178be6fb0ef91fb90d009c0e68007cb801020e07ba00008bda32f0d1ea8af7528bde50cd13 }


condition:
	$a0
}