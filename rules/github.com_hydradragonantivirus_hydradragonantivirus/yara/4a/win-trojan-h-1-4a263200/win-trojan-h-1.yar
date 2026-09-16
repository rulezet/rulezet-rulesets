rule Win_Trojan_H_1
{
strings:
	$a0 = { b90004b43f33d22eff3660011fcd21 }


condition:
	$a0
}