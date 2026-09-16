rule Win_Trojan_Trivial_150
{
strings:
	$a0 = { b44eba100033c9cd21b43cba9e00cd212a2e2a0087cab740 }


condition:
	$a0
}