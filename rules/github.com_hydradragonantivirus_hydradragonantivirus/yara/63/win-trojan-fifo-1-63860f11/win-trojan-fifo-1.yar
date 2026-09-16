rule Win_Trojan_Fifo_1
{
strings:
	$a0 = { 7403e9d300505351521e0655b419cd2150feca7804 }


condition:
	$a0
}