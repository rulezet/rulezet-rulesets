rule anti_debug__Softice_____SICE__8_byt_STR_9_
{
strings:
	$a0 = { 5c5c2e5c5349434500 }

condition:
	$a0
}