rule Win_Trojan_Trivial_212
{
strings:
	$a0 = { b44eba210133c9cd21ba9e00b8023dcd2193ba0001b127b440cd21b43ecd21cd }


condition:
	$a0
}