rule Win_Trojan_Bika_1
{
strings:
	$a0 = { 81e1dfdfdfdf81f94b45524e75108b4e046681e1dfdf81f9454c3332 }


condition:
	$a0
}