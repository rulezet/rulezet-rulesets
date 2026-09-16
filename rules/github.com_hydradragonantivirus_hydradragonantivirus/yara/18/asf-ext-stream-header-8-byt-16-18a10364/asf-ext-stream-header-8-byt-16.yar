rule asf_ext_stream_header__8_byt_16_
{
strings:
	$a0 = { cba5e61472c632438399a96952065b5a }

condition:
	$a0
}