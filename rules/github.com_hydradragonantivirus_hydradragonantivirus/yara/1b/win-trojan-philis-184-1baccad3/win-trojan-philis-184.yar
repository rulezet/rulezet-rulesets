rule Win_Trojan_Philis_184
{
strings:
	$a0 = { 5389042452515983c40456575f5753 }


condition:
	$a0
}