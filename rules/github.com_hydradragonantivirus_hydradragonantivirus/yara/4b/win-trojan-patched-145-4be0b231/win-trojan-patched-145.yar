rule Win_Trojan_Patched_145
{
strings:
	$a0 = { 2e7064620090[0-64]1d807c8d735d8a0e84c9740b8d460550ffd783c610ebef8d73458b7b4103fb83c7456a00546a406a2057b8??1a807cffd0b9 }


condition:
	$a0
}