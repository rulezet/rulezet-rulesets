rule Win_Trojan_Orion_3
{
strings:
	$a0 = { ab16161f078bc3cb3d004b7406e89fffca02001e06 }


condition:
	$a0
}