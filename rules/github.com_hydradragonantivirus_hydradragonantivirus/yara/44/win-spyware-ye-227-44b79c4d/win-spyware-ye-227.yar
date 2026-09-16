rule Win_Spyware_ye_227
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]e02eea3ffb9acdffa1cef1dbfb98c8 }


condition:
	$a0
}