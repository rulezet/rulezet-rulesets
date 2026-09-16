rule Win_Trojan_Torm_6
{
strings:
	$a0 = { b90004ba0001e80a00eb01909c2e }


condition:
	$a0
}