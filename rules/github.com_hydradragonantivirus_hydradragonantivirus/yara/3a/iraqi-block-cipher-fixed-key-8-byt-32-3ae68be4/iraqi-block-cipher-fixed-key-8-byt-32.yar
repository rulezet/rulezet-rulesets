rule Iraqi_block_cipher_fixed_key__8_byt_32_
{
strings:
	$a0 = { 2ef58a0df4e9ee9a8b1ef15a2fcdab61dfbe1c0ab90d17891ed0fe8fa5651b30 }

condition:
	$a0
}