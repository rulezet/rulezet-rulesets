rule VC1_non_uniform_implicit_quantizers__8_byt_32_
{
strings:
	$a0 = { 000000000000000000060708090a0b0c0d0e0f101112131415161718191b1d1f }

condition:
	$a0
}