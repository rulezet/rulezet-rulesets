rule Win_Trojan_Trivial_78
{
strings:
	$a0 = { cd1032e4cd10be8301b40eac0ac07405cd10ebf7c3b8 }


condition:
	$a0
}