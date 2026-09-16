rule EC_curve__EC_NIST_PRIME_384_SEED__8_byt_20_
{
strings:
	$a0 = { a335926aa319a27a1d00896a6773a4827acdac73 }

condition:
	$a0
}