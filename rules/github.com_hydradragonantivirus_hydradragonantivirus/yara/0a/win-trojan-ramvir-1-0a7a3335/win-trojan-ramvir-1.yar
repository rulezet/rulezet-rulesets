rule Win_Trojan_RamVir_1
{
strings:
	$a0 = { 19b91a0cfdf3a5fc8bf7bf0001ad }


condition:
	$a0
}