rule Win_Trojan_Trivial_491
{
strings:
	$a0 = { 6900ba0001b440cd2161b44eba5f01cd21b8013dba9e00cd218bd8ba0001b440b98800cd21b44f }


condition:
	$a0
}