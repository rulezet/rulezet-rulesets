rule unlzx_table_one__8_byt_32_
{
strings:
	$a0 = { 000000000101020203030404050506060707080809090a0a0b0b0c0c0d0d0e0e }

condition:
	$a0
}