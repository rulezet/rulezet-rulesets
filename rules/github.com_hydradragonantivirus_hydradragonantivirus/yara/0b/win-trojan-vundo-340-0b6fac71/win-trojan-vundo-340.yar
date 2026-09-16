rule Win_Trojan_Vundo_340
{
strings:
	$a0 = { e80?000000[0-10]5ebf??(00|01)0000[0-10]03f7[0-10]8b36[0-25]3bf777[0-10]cd20 }


condition:
	$a0
}