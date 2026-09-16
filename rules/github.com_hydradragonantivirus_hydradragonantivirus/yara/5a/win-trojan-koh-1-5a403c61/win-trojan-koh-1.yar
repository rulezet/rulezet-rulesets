rule Win_Trojan_KOH_1
{
strings:
	$a0 = { d057fbe872e2e8a7007443b80102bb006a41ba8000e81adbbeae6b83c6108b043c80741181feee6b75f133c088263a7c }


condition:
	$a0
}