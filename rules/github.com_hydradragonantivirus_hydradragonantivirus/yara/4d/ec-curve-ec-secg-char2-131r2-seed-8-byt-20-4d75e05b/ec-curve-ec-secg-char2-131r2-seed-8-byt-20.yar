rule EC_curve__EC_SECG_CHAR2_131R2_SEED__8_byt_20_
{
strings:
	$a0 = { 985bd3adbad4d696e676875615175a21b43a97e3 }

condition:
	$a0
}