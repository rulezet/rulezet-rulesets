rule Baseking_RCD__8_byt_12_
{
strings:
	$a0 = { 8dce67bbd5e271b0582c160b }

condition:
	$a0
}