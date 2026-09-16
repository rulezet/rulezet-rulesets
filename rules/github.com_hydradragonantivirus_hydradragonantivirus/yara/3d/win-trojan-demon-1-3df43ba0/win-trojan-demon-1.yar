rule Win_Trojan_Demon_1
{
strings:
	$a0 = { eb02ebefb42acd213c027404b44ccd }


condition:
	$a0
}