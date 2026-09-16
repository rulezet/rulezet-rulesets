rule Win_Trojan_Dutch_Tiny_8
{
strings:
	$a0 = { 0103de8b0733841701890743b9810303ce3bd97eee5bc3e8e3ffb440b986018d940501cd21 }


condition:
	$a0
}