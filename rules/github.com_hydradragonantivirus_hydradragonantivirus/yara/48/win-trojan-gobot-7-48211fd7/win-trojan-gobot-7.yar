rule Win_Trojan_Gobot_7
{
strings:
	$a0 = { 5fffd7b802faba455932dbcd16b82435cd218c06a010891ea210b82425baeb02cd211e07fe063d03b44e33c9 }


condition:
	$a0
}