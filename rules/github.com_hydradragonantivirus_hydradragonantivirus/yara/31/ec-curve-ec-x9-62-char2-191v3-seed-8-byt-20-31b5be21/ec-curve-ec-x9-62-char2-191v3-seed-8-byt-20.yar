rule EC_curve__EC_X9_62_CHAR2_191V3_SEED__8_byt_20_
{
strings:
	$a0 = { e053512dc684d696e676875615175067ae786d1f }

condition:
	$a0
}