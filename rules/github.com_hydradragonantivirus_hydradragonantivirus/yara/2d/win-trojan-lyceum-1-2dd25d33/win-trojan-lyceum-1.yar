rule Win_Trojan_Lyceum_1
{
strings:
	$a0 = { ab74f32e803e4007ff74e480fc4e740580fc4f7525 }


condition:
	$a0
}