rule Win_Trojan_Trivial_187
{
strings:
	$a0 = { b44eba2001b92400cd21ba9e00b8023dcd219383c262b440cd21b43ecd21 }


condition:
	$a0
}