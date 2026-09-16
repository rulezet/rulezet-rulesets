rule Win_Trojan_Trivial_409
{
strings:
	$a0 = { 40eb01e9b601eb01e9b200eb01e98aeaeb01e9b1cbeb01e9cd21eb01e9b43eeb01e9cd21eb01e9 }


condition:
	$a0
}