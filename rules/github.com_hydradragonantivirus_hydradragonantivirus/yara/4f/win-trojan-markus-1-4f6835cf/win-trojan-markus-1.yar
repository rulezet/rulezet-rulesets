rule Win_Trojan_Markus_1
{
strings:
	$a0 = { 6b15999a99a355ceb929d933551e43128b0fd41c876ae3ab47a2fb9b7cfb7845335e6ff82af4e886 }


condition:
	$a0
}