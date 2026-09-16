rule Win_Trojan__0274_0006_001_1
{
strings:
	$a0 = { a30601b440cd2132c0e812008bd7b440cd21b43ecd21b44febc757f3a4c351529933c9b442cd }


condition:
	$a0
}