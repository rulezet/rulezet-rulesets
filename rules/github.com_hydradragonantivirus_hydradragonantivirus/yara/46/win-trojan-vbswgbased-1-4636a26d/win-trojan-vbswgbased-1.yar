rule Win_Trojan_VBSWGbased_1
{
strings:
	$a0 = { 6f6e653d6d696428732c692c3129[0-53]633d63266d6964286b2c6a2c31293a666c61673d74727565 }


condition:
	$a0
}