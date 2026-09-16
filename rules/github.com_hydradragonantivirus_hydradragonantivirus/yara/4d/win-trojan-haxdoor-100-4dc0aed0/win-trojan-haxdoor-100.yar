rule Win_Trojan_Haxdoor_100
{
strings:
	$a0 = { 70733a2f2f8442fc063c652d676f6c64002ff777f6db2c2f0079776964a3323117686569675d9adde07d193235 }


condition:
	$a0
}