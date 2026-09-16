rule Win_Trojan_W_123
{
strings:
	$a0 = { e8000000005e83ee07b0f0bb1f000000b96c05000030041e430411e2f8 }


condition:
	$a0
}