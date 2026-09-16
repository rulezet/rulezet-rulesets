rule Win_Trojan_Flame_3
{
strings:
	$a0 = { 4c00b906008bf3bf647ca5a581c6c3038bfead48abd3e0 }


condition:
	$a0
}