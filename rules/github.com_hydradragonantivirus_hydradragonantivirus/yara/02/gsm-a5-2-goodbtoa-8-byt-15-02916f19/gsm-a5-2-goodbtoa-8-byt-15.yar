rule GSM_A5_2_goodBtoA__8_byt_15_
{
strings:
	$a0 = { 4800d4328e16a14dcd7b9722265100 }

condition:
	$a0
}