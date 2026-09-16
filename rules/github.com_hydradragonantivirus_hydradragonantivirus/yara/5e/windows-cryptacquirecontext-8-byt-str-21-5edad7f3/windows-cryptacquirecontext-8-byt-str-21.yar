rule Windows_CryptAcquireContext__8_byt_STR_21_
{
strings:
	$a0 = { 437279707441637175697265436f6e746578744100 }

condition:
	$a0
}