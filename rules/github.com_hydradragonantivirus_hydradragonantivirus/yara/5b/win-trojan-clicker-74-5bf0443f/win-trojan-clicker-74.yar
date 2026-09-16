rule Win_Trojan_Clicker_74
{
strings:
	$a0 = { 558bec83c4f4a1b0404000c60001b864384000e8acfeffff6a036a006a0068c838400068f83840006a00e839ffffff }


condition:
	$a0
}