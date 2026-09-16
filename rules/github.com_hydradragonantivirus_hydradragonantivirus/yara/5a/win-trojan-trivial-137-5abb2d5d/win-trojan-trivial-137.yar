rule Win_Trojan_Trivial_137
{
strings:
	$a0 = { b44eba1800cd21b8023dba9e00cd2193b440 }


condition:
	$a0
}