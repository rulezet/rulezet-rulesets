rule Win_Trojan_Tequila_8
{
strings:
	$a0 = { feb91c00ba490ae8fbfdc35532e4cd1a }


condition:
	$a0
}