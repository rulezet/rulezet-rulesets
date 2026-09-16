rule Win_Trojan_W_257
{
strings:
	$a0 = { 33c96a0f5168ff0000005151516a016a02cd205300010083c4200bd275 }


condition:
	$a0
}