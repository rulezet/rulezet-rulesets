rule Win_Trojan_V2000_1
{
strings:
	$a0 = { f69489072e81bcbd074d5a740efa8b }


condition:
	$a0
}