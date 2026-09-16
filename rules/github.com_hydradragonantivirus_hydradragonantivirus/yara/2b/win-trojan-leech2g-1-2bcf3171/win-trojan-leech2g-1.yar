rule Win_Trojan_Leech2G_1
{
strings:
	$a0 = { 3d004b746180fc3e747480fc11740a80fc127405ea }


condition:
	$a0
}