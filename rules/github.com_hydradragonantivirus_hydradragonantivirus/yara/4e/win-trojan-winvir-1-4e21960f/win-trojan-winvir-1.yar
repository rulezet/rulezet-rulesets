rule Win_Trojan_WinVir_1
{
strings:
	$a0 = { 01e87201baa801b9ae0290e82f01e85201baa801b9ae }


condition:
	$a0
}