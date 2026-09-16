rule EC_curve__EC_SECG_PRIME_160R1_SEED__8_byt_20_
{
strings:
	$a0 = { 1053cde42c14d696e67687561517533bf3f83345 }

condition:
	$a0
}