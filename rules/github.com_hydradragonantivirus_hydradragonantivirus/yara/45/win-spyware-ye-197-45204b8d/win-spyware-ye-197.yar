rule Win_Spyware_ye_197
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]c208cc19dd84376103a8cb3d6502b2 }


condition:
	$a0
}