rule GSM_table_gsm_FAC__16_lil_16_
{
strings:
	$a0 = { ff47ff4fff57ff5fff67ff6fff77ff7f }

condition:
	$a0
}