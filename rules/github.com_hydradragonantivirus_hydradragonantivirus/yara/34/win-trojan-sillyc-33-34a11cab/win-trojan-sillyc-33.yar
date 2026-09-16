rule Win_Trojan_SillyC_33
{
strings:
	$a0 = { b440cd21b43ecd2103f5b44fcd2173bec32bd22b }


condition:
	$a0
}