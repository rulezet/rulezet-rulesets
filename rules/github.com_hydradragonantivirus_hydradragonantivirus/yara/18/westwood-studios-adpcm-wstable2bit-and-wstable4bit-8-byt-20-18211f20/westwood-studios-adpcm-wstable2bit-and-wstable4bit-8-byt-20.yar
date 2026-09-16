rule Westwood_Studios_ADPCM__WSTable2bit_and_WSTable4bit___8_byt_20_
{
strings:
	$a0 = { FEFF0001F7F8FAFBFCFDFEFF0001020304050608 }

condition:
	$a0
}