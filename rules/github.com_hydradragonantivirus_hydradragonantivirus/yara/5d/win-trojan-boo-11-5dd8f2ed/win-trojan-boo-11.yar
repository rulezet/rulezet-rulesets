rule Win_Trojan_BOO_11
{
strings:
	$a0 = { 3d0b00b80102743550b901008a7f0a53b702cd1372253a59bf75073a59c17502faf4e853017414 }


condition:
	$a0
}