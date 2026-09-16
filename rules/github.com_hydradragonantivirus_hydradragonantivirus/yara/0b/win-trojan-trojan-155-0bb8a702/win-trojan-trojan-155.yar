rule Win_Trojan_Trojan_155
{
strings:
	$a0 = { 4b7403e945025053521e06b8023dcd217303e931 }


condition:
	$a0
}