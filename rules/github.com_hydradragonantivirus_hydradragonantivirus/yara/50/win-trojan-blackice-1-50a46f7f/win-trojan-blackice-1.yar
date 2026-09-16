rule Win_Trojan_BlackIce_1
{
strings:
	$a0 = { d0e0fdbf8807b9073b80ec7935ff000e1f0680c151bba00003d08b0d33caf7d242428b053bd1505980fb5480f1bca9 }


condition:
	$a0
}