rule Win_Trojan_ReplayII_3
{
strings:
	$a0 = { 750f814402b202b440b90700bae800cd2133c0e81a00b440bae400b90400cd21b43ecd21 }


condition:
	$a0
}