rule Win_Trojan_Patoruzu_1
{
strings:
	$a0 = { e800005e5683c6170e1f8bde81c3a303ac2c0a8844ff3bf375f6686a1028a6205e1811c3 }


condition:
	$a0
}