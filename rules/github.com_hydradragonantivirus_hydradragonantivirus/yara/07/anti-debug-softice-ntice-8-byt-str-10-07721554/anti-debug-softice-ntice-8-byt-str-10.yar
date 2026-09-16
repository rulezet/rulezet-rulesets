rule anti_debug__Softice_____NTICE__8_byt_STR_10_
{
strings:
	$a0 = { 5c5c2e5c4e5449434500 }

condition:
	$a0
}