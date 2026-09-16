rule EC_curve__EC_SECG_PRIME_160R2_SEED__8_byt_20_
{
strings:
	$a0 = { b99b99b099b323e02709a4d696e6768756151751 }

condition:
	$a0
}