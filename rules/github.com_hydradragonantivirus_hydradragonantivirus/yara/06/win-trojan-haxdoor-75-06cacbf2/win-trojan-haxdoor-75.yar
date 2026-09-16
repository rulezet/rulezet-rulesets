rule Win_Trojan_Haxdoor_75
{
strings:
	$a0 = { df80fffb4572631f68747470733a2f2f3c652d676f6c7e9b508864002f2c2f0079776964bceffecea3323117686569675d19 }


condition:
	$a0
}