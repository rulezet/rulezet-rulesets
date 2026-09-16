rule GSM_table_gsm_MIC__16_lil_16_
{
strings:
	$a0 = { E0FFE0FFF0FFF0FFF8FFF8FFFCFFFCFF }

condition:
	$a0
}