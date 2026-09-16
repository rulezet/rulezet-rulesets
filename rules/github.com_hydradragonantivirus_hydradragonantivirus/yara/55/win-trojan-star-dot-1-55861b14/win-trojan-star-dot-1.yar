rule Win_Trojan_Star_Dot_1
{
strings:
	$a0 = { 3bcd21b42acd21fec08b16410383e2073ac2 }


condition:
	$a0
}