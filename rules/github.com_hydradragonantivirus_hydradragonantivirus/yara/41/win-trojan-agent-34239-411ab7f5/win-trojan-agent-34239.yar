rule Win_Trojan_Agent_34239
{
strings:
	$a0 = { e80200000040f343e8010000002183ecfc4b83ecfc83ec0487cb81c17bafefe281c7ecb2dc1feb059a06f33ebe }


condition:
	$a0
}