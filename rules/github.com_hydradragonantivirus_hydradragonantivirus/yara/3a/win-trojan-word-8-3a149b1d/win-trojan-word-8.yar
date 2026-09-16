rule Win_Trojan_Word_8
{
strings:
	$a0 = { 8b870000a300018a870200a2020153b84230b96719bb917633d2cd21 }


condition:
	$a0
}