rule Win_Trojan_SwedishBoysWW_1
{
strings:
	$a0 = { 018a27bb02018a0786c40503008bf0b41a8d94c80283 }


condition:
	$a0
}