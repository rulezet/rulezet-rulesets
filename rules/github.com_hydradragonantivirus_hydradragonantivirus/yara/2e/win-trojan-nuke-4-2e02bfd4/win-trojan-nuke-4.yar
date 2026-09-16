rule Win_Trojan_Nuke_4
{
strings:
	$a0 = { 40b93004ba0001e80a00eb01909c2e }


condition:
	$a0
}