rule Win_Trojan_MiniB_2
{
strings:
	$a0 = { 8f068e0158050010508f0693015007e88100be00018bfeb9cc00fcf3a4eb6f061e078d36cc01bf0001b99c77f3a5 }


condition:
	$a0
}