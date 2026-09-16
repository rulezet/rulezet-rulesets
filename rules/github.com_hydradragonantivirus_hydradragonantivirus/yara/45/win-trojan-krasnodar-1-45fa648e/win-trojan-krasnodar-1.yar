rule Win_Trojan_Krasnodar_1
{
strings:
	$a0 = { fc8db7????bf0001b90300f3a4b8bb0bcd213c4c7447 }


condition:
	$a0
}