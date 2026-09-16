rule Win_Trojan_Enigma_1
{
strings:
	$a0 = { 03f38904bef40681ee030103f38cc089 }


condition:
	$a0
}