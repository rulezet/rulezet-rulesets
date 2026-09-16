rule Win_Trojan_Spooky_16
{
strings:
	$a0 = { 0900550000000000ffff1403000055000000030000001403 }


condition:
	$a0
}