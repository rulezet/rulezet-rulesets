rule Win_Trojan_Vundo_339
{
strings:
	$a0 = { e80?000000[0-10]59bf??(00|01)0000[0-10]03cf[0-10]8b09[0-25]3bcf77[0-10]cd20 }


condition:
	$a0
}