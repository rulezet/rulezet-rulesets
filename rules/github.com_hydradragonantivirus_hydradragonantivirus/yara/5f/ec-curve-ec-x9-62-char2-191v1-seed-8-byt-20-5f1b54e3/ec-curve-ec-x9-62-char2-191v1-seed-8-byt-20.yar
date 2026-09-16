rule EC_curve__EC_X9_62_CHAR2_191V1_SEED__8_byt_20_
{
strings:
	$a0 = { 4e13ca542744d696e67687561517552f279a8c84 }

condition:
	$a0
}