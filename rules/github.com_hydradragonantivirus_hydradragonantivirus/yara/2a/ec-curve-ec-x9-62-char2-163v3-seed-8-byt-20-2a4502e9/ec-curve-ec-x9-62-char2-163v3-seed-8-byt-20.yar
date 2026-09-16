rule EC_curve__EC_X9_62_CHAR2_163V3_SEED__8_byt_20_
{
strings:
	$a0 = { 50cbf1d95ca94d696e676875615175f16a36a3b8 }

condition:
	$a0
}