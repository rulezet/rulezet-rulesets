rule Win_Trojan_Buzus_38
{
strings:
	$a0 = { 558becb95c0000006a006a004975f9b8f4524000e873f0ffff33c05568ed6740 }


condition:
	$a0
}