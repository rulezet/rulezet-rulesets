rule Win_Trojan_Trivial_346
{
strings:
	$a0 = { 01b94700b440cd21b43ecd21b44fcd2173e3e9bffe2a }


condition:
	$a0
}