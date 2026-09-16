rule Win_Trojan_Caterpillar_1
{
strings:
	$a0 = { 06bf0001be3101b90c00f2a4061fb800015033c0cb }


condition:
	$a0
}