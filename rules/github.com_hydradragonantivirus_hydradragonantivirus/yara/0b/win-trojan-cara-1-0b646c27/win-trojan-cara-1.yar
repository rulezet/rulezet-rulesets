rule Win_Trojan_CARA_1
{
strings:
	$a0 = { 2e0200c000b44ab800b0cd2181ebc0 }


condition:
	$a0
}