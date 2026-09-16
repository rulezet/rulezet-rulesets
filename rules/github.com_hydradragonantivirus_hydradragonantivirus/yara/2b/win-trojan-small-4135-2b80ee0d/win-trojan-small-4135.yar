rule Win_Trojan_Small_4135
{
strings:
	$a0 = { eb1150ff16816c05014265622683c50439efc3e817000000be3f }


condition:
	$a0
}