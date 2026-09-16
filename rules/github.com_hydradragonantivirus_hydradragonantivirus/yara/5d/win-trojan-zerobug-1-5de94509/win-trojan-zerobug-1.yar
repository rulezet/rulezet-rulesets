rule Win_Trojan_ZeroBug_1
{
strings:
	$a0 = { c91f00cd21b43ecd215a1f59b443b0 }


condition:
	$a0
}