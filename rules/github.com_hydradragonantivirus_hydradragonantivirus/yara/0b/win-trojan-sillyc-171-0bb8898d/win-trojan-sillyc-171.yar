rule Win_Trojan_SillyC_171
{
strings:
	$a0 = { 0e5805101050a36701051000a334021fb41a33d2cd210e1fba3602b92000b44ecd217211e844000e1fba3602b44f }


condition:
	$a0
}