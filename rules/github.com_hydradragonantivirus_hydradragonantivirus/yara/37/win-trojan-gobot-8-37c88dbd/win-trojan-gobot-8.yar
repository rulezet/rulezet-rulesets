rule Win_Trojan_Gobot_8
{
strings:
	$a0 = { 9010555bffd3b802faba455932dbcd16b82435cd218c06a510891ea710b82425baef02cd211e07fe064103b44e33c9 }


condition:
	$a0
}