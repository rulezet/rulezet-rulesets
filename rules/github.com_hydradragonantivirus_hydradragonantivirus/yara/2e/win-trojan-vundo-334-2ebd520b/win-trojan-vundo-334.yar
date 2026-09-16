rule Win_Trojan_Vundo_334
{
strings:
	$a0 = { e80?000000[0-10]5bbf??(00|01)0000[0-10]03df[0-10]8b1b[0-25]3bdf77[0-10]cd20 }


condition:
	$a0
}