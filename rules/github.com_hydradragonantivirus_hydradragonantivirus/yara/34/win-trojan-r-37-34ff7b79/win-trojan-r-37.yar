rule Win_Trojan_R_37
{
strings:
	$a0 = { 03be38018bfefcad331e0301ab49e302ebf559c3ba00018b1efd01b92a02e8dcffb80040cd21e8d4ffc320422b }


condition:
	$a0
}