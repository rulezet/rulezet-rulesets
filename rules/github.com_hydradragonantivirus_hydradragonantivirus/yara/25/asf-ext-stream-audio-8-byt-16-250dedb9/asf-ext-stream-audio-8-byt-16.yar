rule asf_ext_stream_audio__8_byt_16_
{
strings:
	$a0 = { 9d8c1731e1032845b5823df9db22f503 }

condition:
	$a0
}