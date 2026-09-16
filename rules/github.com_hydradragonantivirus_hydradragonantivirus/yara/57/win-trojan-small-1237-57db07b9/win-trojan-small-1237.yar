rule Win_Trojan_Small_1237
{
strings:
	$a0 = { 33c0505068e8014000680c024000680402400050ff15e0014000c3 }


condition:
	$a0
}