rule Win_Trojan_Vundo_330
{
strings:
	$a0 = { e80?000000[0-10]59be??(00|01)0000[0-10]03ce[0-10]8b09[0-25]3bce77[0-10]cd20 }


condition:
	$a0
}