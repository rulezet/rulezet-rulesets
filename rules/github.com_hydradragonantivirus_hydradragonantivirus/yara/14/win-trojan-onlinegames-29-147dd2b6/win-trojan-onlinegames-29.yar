rule Win_Trojan_Onlinegames_29
{
strings:
	$a0 = { 03c413c42dcd62c31c2bc0528bdb5a74064424a57c5e045725 }


condition:
	$a0
}