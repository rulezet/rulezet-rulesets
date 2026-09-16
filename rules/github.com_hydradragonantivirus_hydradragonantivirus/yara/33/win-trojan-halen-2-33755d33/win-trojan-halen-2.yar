rule Win_Trojan_Halen_2
{
strings:
	$a0 = { e8000000005f81c7970000008bf733edfcad87 }


condition:
	$a0
}