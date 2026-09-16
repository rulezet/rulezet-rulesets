rule GSM_table_gsm_H__16_lil_22_
{
strings:
	$a0 = { 7AFF8AFE000006086D1600206D16060800008AFE7AFF }

condition:
	$a0
}