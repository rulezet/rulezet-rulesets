rule Win_Trojan_Possessed_4
{
strings:
	$a0 = { 8c064c01c7064a0152082eff2e4a0156 }


condition:
	$a0
}