rule Win_Trojan_Komut_2
{
strings:
	$a0 = { 4b6f6d757420416c696e6469203a207b626f6c7d7b656f6c7d0d0a00ffffffff080000004b6f6d7574203a }


condition:
	$a0
}