rule Win_Trojan_Banker_6328
{
strings:
	$a0 = { 558bec83c4f0b8b4034300e8130055b0a198 }


condition:
	$a0
}