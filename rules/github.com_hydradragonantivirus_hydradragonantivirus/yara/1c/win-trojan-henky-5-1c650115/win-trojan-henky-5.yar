rule Win_Trojan_Henky_5
{
strings:
	$a0 = { d9d068656e4b795de8000000005d8bcd83e90d81e900[0-2]00898d6a0100008b04246633c080384d74072d }


condition:
	$a0
}