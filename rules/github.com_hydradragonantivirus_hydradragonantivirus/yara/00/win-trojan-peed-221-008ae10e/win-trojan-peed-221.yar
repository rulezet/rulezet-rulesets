rule Win_Trojan_Peed_221
{
strings:
	$a0 = { 7303ffd5c3b9c05f010068ae333d008b34245881c65242030089f25266ad69c0 }


condition:
	$a0
}