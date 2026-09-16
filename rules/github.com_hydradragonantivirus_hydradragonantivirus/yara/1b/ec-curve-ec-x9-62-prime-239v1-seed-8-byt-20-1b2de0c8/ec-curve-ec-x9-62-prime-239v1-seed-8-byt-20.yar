rule EC_curve__EC_X9_62_PRIME_239V1_SEED__8_byt_20_
{
strings:
	$a0 = { e43bb460f0b80cc0c0b075798e948060f8321b7d }

condition:
	$a0
}