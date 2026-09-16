rule Win_Trojan_Trivial_147
{
strings:
	$a0 = { 100133c9cd21b43cba9e00cd212a2e2a0087cab74093cd21b44febe3 }


condition:
	$a0
}