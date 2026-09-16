rule Win_Trojan_Pish_1
{
strings:
	$a0 = { 8d005589e5b800019acd028d0081ec00018dbe00ff165731c0509acf088d00bf58011e57b8ff00509a71098d00 }


condition:
	$a0
}