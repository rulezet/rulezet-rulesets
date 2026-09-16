rule RIPEMD_128_InitState__32_lil_AND_
{
strings:
	$a0 = { 76543210[0-20]01234567[0-20]89abcdef[0-20]fedcba98 }

condition:
	$a0
}