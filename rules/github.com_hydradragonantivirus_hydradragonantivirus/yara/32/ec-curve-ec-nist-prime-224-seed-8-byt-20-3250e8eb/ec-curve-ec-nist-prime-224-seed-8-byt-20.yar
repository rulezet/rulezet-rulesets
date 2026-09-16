rule EC_curve__EC_NIST_PRIME_224_SEED__8_byt_20_
{
strings:
	$a0 = { bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5 }

condition:
	$a0
}