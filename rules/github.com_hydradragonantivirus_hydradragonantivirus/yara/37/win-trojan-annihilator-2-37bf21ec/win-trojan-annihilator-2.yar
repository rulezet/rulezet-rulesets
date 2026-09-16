rule Win_Trojan_Annihilator_2
{
strings:
	$a0 = { e800005b81eb0a018db72b01e80200eb13b918018bfeba }


condition:
	$a0
}