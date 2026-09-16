rule Win_Trojan_VGEN_638
{
strings:
	$a0 = { eb00e800005d81ed0501501e06b8cdabcd13eb03e9b10081fbcdab7502ebf553515256571e33d28edac43684002e89b6 }


condition:
	$a0
}