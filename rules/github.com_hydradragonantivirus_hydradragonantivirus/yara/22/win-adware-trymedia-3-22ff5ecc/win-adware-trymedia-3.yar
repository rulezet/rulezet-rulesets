rule Win_Adware_Trymedia_3
{
strings:
	$a0 = { 687474703a2f2f66652e7472796d656469612e636f6d2f612e61 }


condition:
	$a0
}