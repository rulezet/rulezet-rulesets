rule MS_ADPCM_AdaptationTable__16_big_32_
{
strings:
	$a0 = { 00e600e600e600e601330199020002660300026602000199013300e600e600e6 }

condition:
	$a0
}