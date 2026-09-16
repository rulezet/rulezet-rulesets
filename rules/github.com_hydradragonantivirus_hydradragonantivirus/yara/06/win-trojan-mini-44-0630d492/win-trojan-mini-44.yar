rule Win_Trojan_Mini_44
{
strings:
	$a0 = { ba1e01cd21b8023dba9e00cd2193ba0001b440b123cd21b43ecd21c32b }


condition:
	$a0
}