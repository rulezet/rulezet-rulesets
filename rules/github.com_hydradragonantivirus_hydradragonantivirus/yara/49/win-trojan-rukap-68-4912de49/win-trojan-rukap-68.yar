rule Win_Trojan_Rukap_68
{
strings:
	$a0 = { ea0bea8bf7a4188b3abacb8ac699786c2dae6b03e347474fd830263cf79f6c1a4ee34cd3deaaaff55f403a1ecc3b0d023b085bb293cee6754d4437f4f5b8c731c8 }


condition:
	$a0
}