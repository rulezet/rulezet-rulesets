rule Win_Trojan_Tiny_7
{
strings:
	$a0 = { 9195ac3c4d74c83ce97523872c81c50301392c7219896c2c8954268cdab440cd21b8004299 }


condition:
	$a0
}