rule GSM_table_gsm_MAC__16_lil_16_
{
strings:
	$a0 = { 1f001f000f000f000700070003000300 }

condition:
	$a0
}