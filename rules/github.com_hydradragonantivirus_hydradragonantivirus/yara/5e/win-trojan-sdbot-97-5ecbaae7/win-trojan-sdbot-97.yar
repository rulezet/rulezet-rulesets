rule Win_Trojan_Sdbot_97
{
strings:
	$a0 = { 558becb9600000006a006a004975f9b8b0984000e8d7b7ffff33c0556872a940 }


condition:
	$a0
}