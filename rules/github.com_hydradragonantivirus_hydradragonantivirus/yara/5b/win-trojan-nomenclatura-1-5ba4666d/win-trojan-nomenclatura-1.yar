rule Win_Trojan_Nomenclatura_1
{
strings:
	$a0 = { bc02b413cd2f5a0733ff0e1fff842601 }


condition:
	$a0
}