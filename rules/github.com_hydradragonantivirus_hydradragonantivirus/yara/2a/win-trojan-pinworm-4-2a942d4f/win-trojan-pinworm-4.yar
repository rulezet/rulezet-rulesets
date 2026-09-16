rule Win_Trojan_Pinworm_4
{
strings:
	$a0 = { 04e1bff105a0bd1bbea171b24264e4f15759 }


condition:
	$a0
}