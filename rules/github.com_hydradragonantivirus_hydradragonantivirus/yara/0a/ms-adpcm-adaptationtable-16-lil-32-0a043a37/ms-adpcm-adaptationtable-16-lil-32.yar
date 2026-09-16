rule MS_ADPCM_AdaptationTable__16_lil_32_
{
strings:
	$a0 = { e600e600e600e600330199010002660200036602000299013301e600e600e600 }

condition:
	$a0
}