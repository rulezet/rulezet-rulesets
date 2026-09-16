rule Win_Trojan_Warpcom2_2
{
strings:
	$a0 = { 9000833e9000037d0731c09ad8005100bf3e001e57b83f0050bf94001e579ab4002f00c406ae00 }


condition:
	$a0
}