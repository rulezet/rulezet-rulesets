rule Win_Trojan_Mix_3
{
strings:
	$a0 = { c08ec02680261704bf26800e1704 }


condition:
	$a0
}