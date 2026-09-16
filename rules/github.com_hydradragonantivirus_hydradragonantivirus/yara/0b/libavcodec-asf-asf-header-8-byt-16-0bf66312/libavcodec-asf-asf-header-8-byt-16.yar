rule libavcodec_ASF_asf_header__8_byt_16_
{
strings:
	$a0 = { 3026b2758e66cf11a6d900aa0062ce6c }

condition:
	$a0
}