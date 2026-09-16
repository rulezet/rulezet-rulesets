rule GSM_table_gsm_MIC__16_big_16_
{
strings:
	$a0 = { FFE0FFE0FFF0FFF0FFF8FFF8FFFCFFFC }

condition:
	$a0
}