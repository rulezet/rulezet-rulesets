rule Win_Trojan_EMS_1
{
strings:
	$a0 = { 8b1e010181c30301e80a008bfe8d7703a4a561ffe653 }


condition:
	$a0
}