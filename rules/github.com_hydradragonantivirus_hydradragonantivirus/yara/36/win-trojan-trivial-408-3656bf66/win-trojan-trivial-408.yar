rule Win_Trojan_Trivial_408
{
strings:
	$a0 = { 01e8b601eb01e8b200eb01e88aeaeb01e8b1cbeb01e8cd21eb01e8b43eeb01e8cd21eb01e8 }


condition:
	$a0
}