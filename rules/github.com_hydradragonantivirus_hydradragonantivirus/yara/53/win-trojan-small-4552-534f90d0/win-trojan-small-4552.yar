rule Win_Trojan_Small_4552
{
strings:
	$a0 = { 81c0b9d7420052515050ff108daabebc }


condition:
	$a0
}