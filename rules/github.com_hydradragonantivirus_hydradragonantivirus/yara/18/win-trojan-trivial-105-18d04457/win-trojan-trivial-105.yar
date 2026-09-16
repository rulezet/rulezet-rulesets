rule Win_Trojan_Trivial_105
{
strings:
	$a0 = { b44eba1501cd21b8023dba9e00cd2193b44049cd21 }


condition:
	$a0
}