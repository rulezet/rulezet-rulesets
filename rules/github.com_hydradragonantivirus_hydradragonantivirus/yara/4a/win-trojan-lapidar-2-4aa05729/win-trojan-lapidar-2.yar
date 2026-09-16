rule Win_Trojan_Lapidar_2
{
strings:
	$a0 = { 40b902008d96cd01cd21b8024233c933d2cd21b440b912008d96de01cd21b440b9b7018d961200 }


condition:
	$a0
}