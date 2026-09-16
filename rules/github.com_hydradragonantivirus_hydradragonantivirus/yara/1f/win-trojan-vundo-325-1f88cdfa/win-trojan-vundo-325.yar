rule Win_Trojan_Vundo_325
{
strings:
	$a0 = { e80?000000[0-10]5bb9??(00|01)0000[0-10]03d9[0-10]8b1b[0-25]3bd977[0-10]cd20 }


condition:
	$a0
}