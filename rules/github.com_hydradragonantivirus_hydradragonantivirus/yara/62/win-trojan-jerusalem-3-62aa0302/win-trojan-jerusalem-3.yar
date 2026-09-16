rule Win_Trojan_Jerusalem_3
{
strings:
	$a0 = { 05e0f9060e071f8bd7b8004b83c203bb3f009c26ff1e }


condition:
	$a0
}