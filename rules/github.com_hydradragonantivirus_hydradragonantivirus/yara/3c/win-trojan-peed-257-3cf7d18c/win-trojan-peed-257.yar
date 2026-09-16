rule Win_Trojan_Peed_257
{
strings:
	$a0 = { e8a000000068a4b000005981c1508d000081c1a4b0000068ae??2d005e565881c6 }


condition:
	$a0
}