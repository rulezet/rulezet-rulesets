rule EC_curve__EC_NIST_PRIME_192_SEED__8_byt_20_
{
strings:
	$a0 = { 3045ae6fc8422f64ed579528d38120eae12196d5 }

condition:
	$a0
}