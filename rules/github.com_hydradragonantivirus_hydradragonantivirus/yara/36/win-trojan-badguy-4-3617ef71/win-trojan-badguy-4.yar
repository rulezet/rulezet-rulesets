rule Win_Trojan_BadGuy_4
{
strings:
	$a0 = { b44ccd21ba000190b44090b90901 }


condition:
	$a0
}