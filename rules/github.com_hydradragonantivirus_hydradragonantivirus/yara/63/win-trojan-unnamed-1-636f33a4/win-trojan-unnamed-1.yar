rule Win_Trojan_Unnamed_1
{
strings:
	$a0 = { fe8bae220281c5030133f6e80000e800005d8b9e1402b440cd21b801578b9e14028b8e18028b }


condition:
	$a0
}