rule Win_Trojan_FathMac_6
{
strings:
	$a0 = { c0be240183ea00b92d0781e9240188e488f689c9268a0280c70034642688024688dbe2ee88c0c3 }


condition:
	$a0
}