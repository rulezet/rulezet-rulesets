rule EC_curve__EC_SECG_PRIME_112R2_SEED__8_byt_20_
{
strings:
	$a0 = { 002757a1114d696e6768756151755316c05e0bd4 }

condition:
	$a0
}