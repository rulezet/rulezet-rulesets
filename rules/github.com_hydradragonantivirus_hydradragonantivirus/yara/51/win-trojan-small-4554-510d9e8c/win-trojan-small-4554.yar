rule Win_Trojan_Small_4554
{
strings:
	$a0 = { 81c0d8d7420068452345006852329800 }


condition:
	$a0
}