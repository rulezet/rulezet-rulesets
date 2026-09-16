rule Half_Life_packets_decoding_encoding_function_key__8_byt_16_
{
strings:
	$a0 = { 05617aed1bca0d9b4af164c7b58edfa0 }

condition:
	$a0
}