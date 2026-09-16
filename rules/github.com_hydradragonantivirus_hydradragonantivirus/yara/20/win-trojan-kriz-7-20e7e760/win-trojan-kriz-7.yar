rule Win_Trojan_Kriz_7
{
strings:
	$a0 = { 9c9c60b98ee31500e801000000045b81c18e022000b8b1 }


condition:
	$a0
}