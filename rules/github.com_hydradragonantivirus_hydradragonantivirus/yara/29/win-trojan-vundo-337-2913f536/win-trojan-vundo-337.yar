rule Win_Trojan_Vundo_337
{
strings:
	$a0 = { e80?000000[0-10]5bbe??(00|01)0000[0-10]03de[0-10]8b1b[0-25]3bde77[0-10]cd20 }


condition:
	$a0
}