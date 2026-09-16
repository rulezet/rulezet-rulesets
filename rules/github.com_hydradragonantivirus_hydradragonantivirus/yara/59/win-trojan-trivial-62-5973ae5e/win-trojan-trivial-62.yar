rule Win_Trojan_Trivial_62
{
strings:
	$a0 = { 4eba3b01cd217231b80043ba9e00cd21512bc9b80143cd21b8023dcd2193b440b98100ba0001cd21b43ecd21b80143 }


condition:
	$a0
}