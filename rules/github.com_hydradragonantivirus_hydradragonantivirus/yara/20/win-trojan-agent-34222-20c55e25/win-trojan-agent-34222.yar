rule Win_Trojan_Agent_34222
{
strings:
	$a0 = { 558bec51518b4508a364db01108b450c8945fc8b45fc8945f8836df8017402eb2f74267524e8 }


condition:
	$a0
}