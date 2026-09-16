rule Win_Trojan_Voyager_1
{
strings:
	$a0 = { be4104e9750780be440421741380be42045a750780be41 }


condition:
	$a0
}