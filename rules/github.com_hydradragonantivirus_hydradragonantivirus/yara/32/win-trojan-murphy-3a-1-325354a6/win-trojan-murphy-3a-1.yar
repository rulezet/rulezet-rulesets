rule Win_Trojan_Murphy_3A_1
{
strings:
	$a0 = { b419cd218886f804bbffff899e3c05c3 }


condition:
	$a0
}