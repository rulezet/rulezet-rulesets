rule Win_Trojan_Mini_47
{
strings:
	$a0 = { ba0001b98e01cd21e80200c300be03018bfe8a267a02b96601ac32c4aae2fac3 }


condition:
	$a0
}