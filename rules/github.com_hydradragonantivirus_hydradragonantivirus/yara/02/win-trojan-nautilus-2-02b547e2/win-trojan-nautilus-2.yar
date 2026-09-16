rule Win_Trojan_Nautilus_2
{
strings:
	$a0 = { 33c933d2cd21b440b903008d96eb03cd21b8024233c933d2cd218db603018dbe6d08b92007 }


condition:
	$a0
}