rule Win_Trojan_Scorpio_2
{
strings:
	$a0 = { aaff74663d004b74db80fc3d741480fc43740f80fc1174 }


condition:
	$a0
}