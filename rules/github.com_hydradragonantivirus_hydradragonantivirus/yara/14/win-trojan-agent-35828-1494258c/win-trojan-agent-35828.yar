rule Win_Trojan_Agent_35828
{
strings:
	$a0 = { 437265617465642062792042756c6c204d6f6f7365 }


condition:
	$a0
}