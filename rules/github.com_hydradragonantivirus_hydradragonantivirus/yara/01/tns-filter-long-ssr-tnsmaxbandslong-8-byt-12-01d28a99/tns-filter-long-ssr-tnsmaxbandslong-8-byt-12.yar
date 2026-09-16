rule TNS_filter_long_SSR_tnsMaxBandsLong__8_byt_12_
{
strings:
	$a0 = { 1c1c1b1a1a1a1d1d17171713 }

condition:
	$a0
}