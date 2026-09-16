rule anti_debug__Vista_anti_debug__no_name___8_byt_29_
{
strings:
	$a0 = { 64ff35000000006489250000000064a11800000005fc0b00008b1885db }

condition:
	$a0
}