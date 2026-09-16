rule S1_clear_and_cipher_family__8_byt_16_
{
strings:
	$a0 = { 810305070204068301fefdfc80818208 }

condition:
	$a0
}