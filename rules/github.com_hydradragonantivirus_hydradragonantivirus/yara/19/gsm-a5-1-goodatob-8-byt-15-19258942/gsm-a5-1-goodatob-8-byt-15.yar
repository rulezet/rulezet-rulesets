rule GSM_A5_1_goodAtoB__8_byt_15_
{
strings:
	$a0 = { 534eaa582fe8151ab6e1855a728c00 }

condition:
	$a0
}