rule Win_Trojan_Banker_4631
{
strings:
	$a0 = { b8a4fa7f005064ff35000000006489250000000033c08908 }

	$a1 = { 600d0b6b65726ee66c0e33322e64[0-15]3300697274 }


condition:
	$a0 and $a1
}