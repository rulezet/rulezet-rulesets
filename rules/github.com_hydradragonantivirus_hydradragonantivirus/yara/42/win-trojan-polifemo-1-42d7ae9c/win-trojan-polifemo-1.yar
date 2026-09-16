rule Win_Trojan_Polifemo_1
{
strings:
	$a0 = { 1e3b01b90300ba0b01cd21b43ecd21c3b43bc6063d015cba3d01cd21bb800183eb02588907 }


condition:
	$a0
}