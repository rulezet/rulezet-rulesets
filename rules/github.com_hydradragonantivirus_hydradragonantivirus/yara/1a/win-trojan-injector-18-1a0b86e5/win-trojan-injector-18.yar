rule Win_Trojan_Injector_18
{
strings:
	$a0 = { 60be005041008dbe00c0feff5789e58d9c2480c1ffff31c05039dc75fb46465368[0-2]03005783c3045368[0-2]020056 }


condition:
	$a0
}