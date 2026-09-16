rule Win_Trojan_VGEN_617
{
strings:
	$a0 = { e800001e06b014e6709090e47124023c02751fe80b00053317191a1c65806f2a005eac3c00740bb435cd218bfbb0cfaa }


condition:
	$a0
}