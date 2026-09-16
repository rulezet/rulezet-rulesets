rule Win_Trojan_PCBB_5
{
strings:
	$a0 = { bcbdec8f7c8f678f758f6e8f4a8f438f51b2b2bba3 }


condition:
	$a0
}